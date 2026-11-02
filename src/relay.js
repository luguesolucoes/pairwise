/* Pairwise automatic pairing: carries the receiver's encrypted connection answer back
 * to the sender through public MQTT-over-WebSocket brokers, so the receiver only has
 * to open the link. Brokers see an opaque AES-GCM blob on a random-looking topic:
 * never the key, never the text, never readable connection details. */
(function (global) {
  'use strict';
  const LT = global.LT;
  const te = new TextEncoder(), td = new TextDecoder();

  const DEFAULT_RELAYS = [
    { url: 'wss://broker.emqx.io:8084/mqtt', label: 'broker.emqx.io' },
    { url: 'wss://broker.hivemq.com:8884/mqtt', label: 'broker.hivemq.com' },
    { url: 'wss://test.mosquitto.org:8081/mqtt', label: 'test.mosquitto.org' }
  ];

  // ---------- minimal MQTT 3.1.1 client (QoS 0 publish/subscribe only) ----------
  function mstr(s) {
    const b = te.encode(s);
    const o = new Uint8Array(2 + b.length);
    o[0] = b.length >> 8; o[1] = b.length & 255; o.set(b, 2);
    return o;
  }
  function packet(type, parts) {
    const len = parts.reduce((a, p) => a + p.length, 0);
    const vi = [];
    let n = len;
    do { let d = n % 128; n = Math.floor(n / 128); if (n > 0) d |= 128; vi.push(d); } while (n > 0);
    const o = new Uint8Array(1 + vi.length + len);
    o[0] = type; o.set(vi, 1);
    let off = 1 + vi.length;
    for (const p of parts) { o.set(p, off); off += p.length; }
    return o;
  }

  class MqttWs {
    constructor(cfg, onEvent) {
      this.cfg = cfg; this.onEvent = onEvent;
      this.subs = new Map(); this.buf = new Uint8Array(0); this.queue = [];
      this.open = false; this.closed = false; this.pid = 1;
    }
    connect() {
      let ws;
      try { ws = new WebSocket(this.cfg.url, 'mqtt'); } catch (e) { this.onEvent('fail', e && e.message ? e.message : String(e)); return; }
      ws.binaryType = 'arraybuffer';
      this.ws = ws;
      ws.onopen = () => {
        const flags = 0x02 | (this.cfg.username ? 0x80 : 0) | (this.cfg.password ? 0x40 : 0);
        const parts = [mstr('MQTT'), new Uint8Array([4, flags, 0, 30]), mstr('pw' + LT.hex(LT.rand(8)))];
        if (this.cfg.username) parts.push(mstr(this.cfg.username));
        if (this.cfg.password) parts.push(mstr(this.cfg.password));
        ws.send(packet(0x10, parts));
      };
      ws.onmessage = (e) => { if (e.data instanceof ArrayBuffer) this.onData(new Uint8Array(e.data)); };
      ws.onerror = () => {};
      ws.onclose = () => {
        const was = this.open;
        this.open = false;
        clearInterval(this.ping); clearTimeout(this.timer);
        if (!this.closed) { this.closed = true; this.onEvent(was ? 'closed' : 'fail', 'connection closed'); }
      };
      this.timer = setTimeout(() => { if (!this.open) { this.onEvent('fail', 'timed out'); this.close(); } }, 10000);
    }
    onData(chunk) {
      const b = new Uint8Array(this.buf.length + chunk.length);
      b.set(this.buf); b.set(chunk, this.buf.length);
      this.buf = b;
      for (;;) {
        if (this.buf.length < 2) return;
        let mult = 1, len = 0, i = 1, byte;
        do {
          if (i >= this.buf.length) return;
          if (i > 4) { this.close(); return; }
          byte = this.buf[i++];
          len += (byte & 127) * mult; mult *= 128;
        } while (byte & 128);
        if (this.buf.length < i + len) return;
        const type = this.buf[0];
        const body = this.buf.slice(i, i + len);
        this.buf = this.buf.slice(i + len);
        this.handle(type, body);
      }
    }
    handle(type, body) {
      const kind = type >> 4;
      if (kind === 2) { // CONNACK
        clearTimeout(this.timer);
        if (body.length < 2 || body[1] !== 0) { this.onEvent('fail', 'refused'); this.close(); return; }
        this.open = true;
        this.ping = setInterval(() => this.send(new Uint8Array([0xC0, 0])), 20000);
        for (const t of this.subs.keys()) this.sendSub(t);
        const q = this.queue; this.queue = [];
        q.forEach((p) => this.send(p));
        this.onEvent('open');
      } else if (kind === 3) { // PUBLISH
        if (body.length < 2) return;
        const qos = (type >> 1) & 3;
        const tl = (body[0] << 8) | body[1];
        const topic = td.decode(body.subarray(2, 2 + tl));
        const off = 2 + tl + (qos > 0 ? 2 : 0);
        const cb = this.subs.get(topic);
        if (cb) cb(body.slice(off));
      }
    }
    send(p) { if (this.ws && this.ws.readyState === 1) { try { this.ws.send(p); } catch (e) { /* ignore */ } } }
    sendSub(topic) {
      const id = (this.pid++ & 0xffff) || 1;
      this.send(packet(0x82, [new Uint8Array([id >> 8, id & 255]), mstr(topic), new Uint8Array([0])]));
    }
    subscribe(topic, cb) { this.subs.set(topic, cb); if (this.open) this.sendSub(topic); }
    publish(topic, bytes) {
      const p = packet(0x30, [mstr(topic), bytes]);
      if (this.open) this.send(p); else if (this.queue.length < 8) this.queue.push(p);
    }
    close() {
      this.closed = true;
      clearTimeout(this.timer); clearInterval(this.ping);
      try { if (this.ws && this.ws.readyState === 1) this.ws.send(new Uint8Array([0xE0, 0])); } catch (e) { /* ignore */ }
      try { if (this.ws) this.ws.close(); } catch (e) { /* ignore */ }
      this.open = false;
    }
  }

  // ---------- encrypted signaling over several brokers at once ----------
  class Signal {
    constructor(sess, relays, onEvent) {
      this.sess = sess;
      this.relays = relays && relays.length ? relays : DEFAULT_RELAYS;
      this.onEvent = onEvent || function () {};
      this.clients = [];
      this.openCount = 0;
      this.failed = 0;
      this.topic = null;
      this.handler = null;
      this.closed = false;
      this.repeat = 0;
    }
    async start() {
      this.topic = await LT.signalTopic(this.sess);
      for (const cfg of this.relays) {
        const c = new MqttWs(cfg, (type, detail) => {
          if (this.closed) return;
          if (type === 'open') { this.openCount++; this.onEvent('log', 'Pairing relay connected: ' + cfg.label); }
          else if (type === 'fail') { this.failed++; this.onEvent('log', 'Pairing relay unavailable: ' + cfg.label + ' (' + detail + ')'); }
          else if (type === 'closed') { this.openCount = Math.max(0, this.openCount - 1); this.onEvent('log', 'Pairing relay disconnected: ' + cfg.label); }
          this.onEvent('status', { open: this.openCount, failed: this.failed, total: this.relays.length });
        });
        if (this.handler) c.subscribe(this.topic, this.handler);
        this.clients.push(c);
        c.connect();
      }
    }
    /** Sender: receive decrypted answers. Messages that fail authentication are ignored. */
    listen(onMessage) {
      let lastSeen = '';
      this.handler = async (bytes) => {
        try {
          const text = await LT.openSignal(this.sess, bytes);
          if (text === lastSeen) return; // the same answer arrives once per relay
          lastSeen = text;
          onMessage(text);
        } catch (e) { /* not ours, or tampered: ignore */ }
      };
      for (const c of this.clients) c.subscribe(this.topic, this.handler);
    }
    /** Receiver: publish the encrypted answer now and every 2.5 s until stopped. */
    async publishRepeatedly(text, maxMs) {
      const sealed = await LT.sealSignal(this.sess, text);
      const t0 = Date.now();
      const send = () => {
        if (this.closed || Date.now() - t0 > (maxMs || 180000)) { this.stopRepeat(); return; }
        for (const c of this.clients) c.publish(this.topic, sealed);
      };
      this.stopRepeat();
      send();
      this.repeat = setInterval(send, 2500);
    }
    stopRepeat() { clearInterval(this.repeat); this.repeat = 0; }
    close() {
      if (this.closed) return;
      this.closed = true;
      this.stopRepeat();
      this.clients.forEach((c) => c.close());
      this.clients = [];
    }
  }

  global.PWR = { Signal, MqttWs, DEFAULT_RELAYS };
})(typeof window !== 'undefined' ? window : globalThis);
