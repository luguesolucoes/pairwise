/* Pairwise transport: WebRTC peer setup with manual (QR) signaling and the
 * sender/receiver transfer protocol. No DOM access; reports through onEvent. */
(function (global) {
  'use strict';
  const LT = global.LT;

  const HIGH_WATER = 4 * 1024 * 1024;   // pause sending above this many buffered bytes
  const LOW_WATER = 1 * 1024 * 1024;    // resume when the buffer drains below this
  const ACK_EVERY = 16;
  const GATHER_TIMEOUT_MS = 5000;
  const SENDER_CONNECT_TIMEOUT_MS = 45000;
  const RECEIVER_CONNECT_TIMEOUT_MS = 180000;
  const STALL_TIMEOUT_MS = 30000;

  function describeCandidate(c) {
    const m = /typ (\w+)/.exec(c.candidate || '');
    const typ = m ? m[1] : 'unknown';
    const proto = (c.protocol || (/ (udp|tcp) /i.exec(c.candidate || '') || [])[1] || '').toLowerCase();
    const labels = { host: 'local network address', srflx: 'public address learned from STUN', relay: 'TURN relay address', prflx: 'peer-reflexive address' };
    return (labels[typ] || typ) + (proto ? ' (' + proto + ')' : '');
  }

  // Resolves when gathering completes, or once candidates exist and none has arrived for
  // QUIET_MS (browsers often keep gathering on unused interfaces), or after `ms` at most.
  const QUIET_MS = 1200;
  function waitForGathering(pc, ms) {
    return new Promise((resolve) => {
      if (pc.iceGatheringState === 'complete') return resolve();
      let quiet = null, seen = 0;
      const hard = setTimeout(done, ms);
      function done() {
        clearTimeout(hard); clearTimeout(quiet);
        pc.removeEventListener('icegatheringstatechange', check);
        pc.removeEventListener('icecandidate', onCand);
        resolve();
      }
      function check() { if (pc.iceGatheringState === 'complete') done(); }
      function onCand(e) {
        if (!e.candidate) return done();
        seen++;
        clearTimeout(quiet);
        quiet = setTimeout(() => { if (seen) done(); }, QUIET_MS);
      }
      pc.addEventListener('icegatheringstatechange', check);
      pc.addEventListener('icecandidate', onCand);
    });
  }

  class Peer {
    constructor(iceServers, emit) {
      this.emit = emit;
      this.pc = new RTCPeerConnection({ iceServers: iceServers || [] });
      this.closed = false;
      this.pc.addEventListener('icecandidate', (e) => {
        if (e.candidate && e.candidate.candidate) this.emit('log', 'Network candidate found: ' + describeCandidate(e.candidate));
      });
      this.pc.addEventListener('connectionstatechange', () => {
        const s = this.pc.connectionState;
        this.emit('log', 'Peer connection: ' + s);
        if (s === 'failed' || s === 'disconnected') this.emit('link-lost', s);
      });
    }
    async localCompact() {
      await waitForGathering(this.pc, GATHER_TIMEOUT_MS);
      return LT.compactSdp(this.pc.localDescription.sdp);
    }
    close() {
      if (this.closed) return;
      this.closed = true;
      try { if (this.dc) this.dc.close(); } catch (e) { /* ignore */ }
      try { this.pc.close(); } catch (e) { /* ignore */ }
    }
  }

  // ------------------------------------------------------------------ Sender
  class Sender {
    constructor(opts) {
      this.text = opts.text;
      this.manifest = opts.manifest;
      this.sess = opts.sess;
      this.iceServers = opts.iceServers;
      this.expiresAt = opts.expiresAt;
      this.onEvent = opts.onEvent || function () {};
      this.peer = null;
      this.pumpGen = 0;
      this.acked = 0;
      this.sent = 0;
      this.verified = false;
      this.destroyed = false;
      this.connectTimer = null;
    }
    emit(type, data) { if (!this.destroyed || type === 'state') this.onEvent(type, data); }

    /** Creates a fresh peer and returns the offer fragment for the QR code. Reuses the session key (resume). */
    async createOffer() {
      if (this.destroyed) throw new Error('Session ended');
      if (this.peer) this.peer.close();
      const peer = new Peer(this.iceServers, (t, d) => this.onPeerEvent(peer, t, d));
      this.peer = peer;
      const dc = peer.pc.createDataChannel('pairwise', { ordered: true });
      dc.binaryType = 'arraybuffer';
      dc.bufferedAmountLowThreshold = LOW_WATER;
      peer.dc = dc;
      dc.addEventListener('open', () => this.onOpen(peer));
      dc.addEventListener('message', (e) => this.onMessage(peer, e.data));
      dc.addEventListener('close', () => { if (peer === this.peer && !this.verified && !this.destroyed) this.emit('disconnected', { resumable: true }); });
      this.emit('log', 'Creating connection offer');
      await peer.pc.setLocalDescription(await peer.pc.createOffer());
      const compact = await peer.localCompact();
      return LT.offerFragment(this.sess, compact);
    }

    async acceptAnswer(code) {
      const ans = LT.parseAnswer(code);
      if (!LT.equalBytes(ans.sid, this.sess.sid)) throw new Error('That answer belongs to a different session');
      if (!this.peer || this.peer.pc.signalingState !== 'have-local-offer') throw new Error('Create a new pairing code first');
      await this.peer.pc.setRemoteDescription({ type: 'answer', sdp: LT.expandSdp(ans.compact) });
      this.emit('state', 'connecting');
      this.emit('log', 'Answer applied; connecting directly to the recipient');
      clearTimeout(this.connectTimer);
      const peer = this.peer;
      this.connectTimer = setTimeout(() => {
        if (peer === this.peer && (!peer.dc || peer.dc.readyState !== 'open')) {
          this.emit('error', 'Could not connect within 45 seconds. The devices may be on networks that block direct connections; a TURN relay would be required.');
        }
      }, SENDER_CONNECT_TIMEOUT_MS);
    }

    onPeerEvent(peer, type, data) {
      if (peer !== this.peer) return;
      if (type === 'link-lost' && !this.verified) this.emit('disconnected', { resumable: true, reason: data });
      else if (type !== 'link-lost') this.emit(type, data);
    }

    onOpen(peer) {
      if (peer !== this.peer) return;
      clearTimeout(this.connectTimer);
      this.emit('state', 'authenticating');
      this.emit('log', 'Data channel open; checking that the recipient holds the key');
      peer.nonce = LT.rand(16);
      peer.dc.send(JSON.stringify({ t: 'chal', n: LT.b64u(peer.nonce) }));
    }

    async onMessage(peer, data) {
      if (peer !== this.peer || typeof data !== 'string') return;
      let msg;
      try { msg = JSON.parse(data); } catch (e) { return; }
      if (msg.t === 'resp') {
        let ok = false;
        try { ok = await LT.authVerify(this.sess, peer.nonce, LT.unb64u(msg.mac)); } catch (e) { ok = false; }
        if (!ok) {
          this.emit('error', 'The device that connected does not hold the session key. Connection closed.');
          peer.close();
          return;
        }
        const from = Number.isSafeInteger(msg.have) && msg.have >= 0 && msg.have <= this.manifest.count ? msg.have : 0;
        this.emit('log', from > 0 ? 'Recipient verified; resuming at chunk ' + from + ' of ' + this.manifest.count : 'Recipient verified; sending');
        this.emit('state', 'sending');
        this.acked = from;
        const mframe = await LT.sealFrame(this.sess, LT.T_MANIFEST, 0, 0, LT.encodeManifest(this.manifest, this.expiresAt));
        peer.dc.send(mframe);
        this.pump(peer, from);
      } else if (msg.t === 'ack' && Number.isSafeInteger(msg.next)) {
        this.acked = Math.max(this.acked, msg.next);
        this.emit('progress', { acked: this.acked, sent: this.sent, count: this.manifest.count, bytes: this.manifest.totalBytes });
      } else if (msg.t === 'done') {
        if (msg.ok) {
          this.verified = true;
          this.acked = this.manifest.count;
          this.emit('progress', { acked: this.acked, sent: this.sent, count: this.manifest.count, bytes: this.manifest.totalBytes });
          this.emit('done', { digest: msg.digest });
        } else {
          this.emit('error', 'Recipient rejected the transfer: ' + String(msg.reason || 'integrity check failed'));
        }
      } else if (msg.t === 'bye') {
        this.emit('log', 'Recipient ended the session');
        this.emit('remote-bye');
      }
    }

    waitLow(dc) {
      return new Promise((resolve) => {
        const done = () => { dc.removeEventListener('bufferedamountlow', done); dc.removeEventListener('close', done); resolve(); };
        dc.addEventListener('bufferedamountlow', done);
        dc.addEventListener('close', done);
      });
    }

    async pump(peer, from) {
      const gen = ++this.pumpGen;
      const dc = peer.dc;
      const { count } = this.manifest;
      const buf = new Uint8Array(this.manifest.chunkBytes);
      try {
        for (let i = from; i < count; i++) {
          if (gen !== this.pumpGen || this.destroyed || dc.readyState !== 'open') return;
          if (dc.bufferedAmount > HIGH_WATER) {
            await this.waitLow(dc);
            if (gen !== this.pumpGen || dc.readyState !== 'open') return;
          }
          const plain = LT.chunkBytesAt(this.text, this.manifest, i, buf);
          const frame = await LT.sealFrame(this.sess, LT.T_DATA, i, count, plain);
          if (dc.readyState !== 'open') return;
          dc.send(frame);
          this.sent = i + 1;
          if ((i & 7) === 7 || i === count - 1) {
            this.emit('progress', { acked: this.acked, sent: this.sent, count, bytes: this.manifest.totalBytes });
          }
        }
        if (count === 0) this.emit('progress', { acked: 0, sent: 0, count: 0, bytes: 0 });
        this.emit('log', 'All encrypted chunks handed to the connection; waiting for the recipient to verify');
      } catch (e) {
        this.emit('error', 'Sending failed: ' + (e && e.message ? e.message : e));
      }
    }

    destroy(notify) {
      if (this.destroyed) return;
      this.pumpGen++;
      clearTimeout(this.connectTimer);
      try { if (notify && this.peer && this.peer.dc && this.peer.dc.readyState === 'open') this.peer.dc.send(JSON.stringify({ t: 'bye' })); } catch (e) { /* ignore */ }
      if (this.peer) { const p = this.peer; setTimeout(() => p.close(), notify ? 150 : 0); }
      this.destroyed = true;
      this.peer = null;
      this.sess = null;       // drop key material references
      this.text = null;
      this.manifest = null;
    }
  }

  // ---------------------------------------------------------------- Receiver
  class Receiver {
    constructor(opts) {
      this.onEvent = opts.onEvent || function () {};
      this.iceServers = opts.iceServers;
      this.sess = null;
      this.manifest = null;
      this.next = 0;
      this.chain = new Uint8Array(32);
      this.parts = [];
      this.receivedBytes = 0;
      this.decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
      this.text = null;
      this.done = false;
      this.destroyed = false;
      this.queue = Promise.resolve();
      this.stallTimer = null;
      this.connectTimer = null;
      this.peer = null;
    }
    emit(type, data) { if (!this.destroyed) this.onEvent(type, data); }

    /** Accepts a parsed offer (from LT.parseOffer) and returns the answer code. Same session id resumes. */
    async acceptOffer(offer) {
      if (this.destroyed) throw new Error('Session ended');
      if (this.sess && !LT.equalBytes(this.sess.sid, offer.sid)) throw new Error('That code belongs to a different session. Clear this one first.');
      if (!this.sess) this.sess = await LT.openSession(offer.sid, offer.key);
      if (this.done) throw new Error('This transfer is already complete');
      if (this.peer) this.peer.close();
      const peer = new Peer(this.iceServers, (t, d) => this.onPeerEvent(peer, t, d));
      this.peer = peer;
      peer.pc.addEventListener('datachannel', (e) => {
        if (peer !== this.peer) return;
        const dc = e.channel;
        dc.binaryType = 'arraybuffer';
        peer.dc = dc;
        dc.addEventListener('open', () => { clearTimeout(this.connectTimer); this.emit('state', 'connected'); this.emit('log', 'Data channel open'); });
        dc.addEventListener('message', (ev) => {
          this.queue = this.queue.then(() => this.onMessage(peer, ev.data)).catch((err) => {
            this.emit('error', 'Receiving failed: ' + (err && err.message ? err.message : err));
          });
        });
        dc.addEventListener('close', () => { if (peer === this.peer && !this.done && !this.destroyed) this.emit('disconnected', { resumable: true }); });
      });
      await peer.pc.setRemoteDescription({ type: 'offer', sdp: LT.expandSdp(offer.compact) });
      await peer.pc.setLocalDescription(await peer.pc.createAnswer());
      const compact = await peer.localCompact();
      clearTimeout(this.connectTimer);
      this.connectTimer = setTimeout(() => {
        if (peer === this.peer && (!peer.dc || peer.dc.readyState !== 'open')) this.emit('error', 'No connection after 3 minutes. Generate a new code on the sender and try again.');
      }, RECEIVER_CONNECT_TIMEOUT_MS);
      return LT.answerCode(this.sess.sid, compact);
    }

    onPeerEvent(peer, type, data) {
      if (peer !== this.peer) return;
      if (type === 'link-lost' && !this.done) this.emit('disconnected', { resumable: true, reason: data });
      else if (type !== 'link-lost') this.emit(type, data);
    }

    armStall(peer) {
      clearTimeout(this.stallTimer);
      if (this.done) return;
      this.stallTimer = setTimeout(() => {
        if (peer === this.peer && !this.done) this.emit('stalled');
      }, STALL_TIMEOUT_MS);
    }

    send(peer, obj) { try { if (peer.dc && peer.dc.readyState === 'open') peer.dc.send(JSON.stringify(obj)); } catch (e) { /* ignore */ } }

    fail(peer, reason) {
      this.send(peer, { t: 'done', ok: false, reason });
      this.emit('error', reason);
      this.parts = [];
      peer.close();
    }

    async onMessage(peer, data) {
      if (peer !== this.peer || this.destroyed) return;
      this.armStall(peer);
      if (typeof data === 'string') {
        let msg;
        try { msg = JSON.parse(data); } catch (e) { return; }
        if (msg.t === 'chal') {
          const mac = await LT.authTag(this.sess, LT.unb64u(msg.n));
          this.emit('state', 'receiving');
          this.send(peer, { t: 'resp', mac: LT.b64u(mac), have: this.next });
        } else if (msg.t === 'bye') {
          this.emit('log', 'Sender ended the session');
          this.emit('remote-bye');
        }
        return;
      }
      const frame = new Uint8Array(data);
      let opened;
      try {
        const hdr = LT.frameHeader(frame);
        if (hdr.type === LT.T_MANIFEST) {
          opened = await LT.openFrame(this.sess, frame, 0);
          const m = LT.decodeManifest(opened.plain);
          if (this.manifest && this.manifest.digest !== m.digest) return this.fail(peer, 'Sender is offering different content than before');
          if (!this.manifest) {
            this.manifest = m;
            this.emit('manifest', m);
            this.emit('log', 'Manifest received: ' + m.count + ' chunks, ' + m.bytes + ' bytes');
          }
          if (m.count === 0) await this.finish(peer);
          return;
        }
        if (hdr.type !== LT.T_DATA || !this.manifest) return this.fail(peer, 'Unexpected data before the manifest');
        if (hdr.index < this.next) return; // duplicate after a resume
        if (hdr.index !== this.next) return this.fail(peer, 'Chunk ' + hdr.index + ' arrived out of order (expected ' + this.next + ')');
        opened = await LT.openFrame(this.sess, frame, this.manifest.count);
      } catch (e) {
        return this.fail(peer, 'A chunk failed authentication. It was altered in transit or encrypted with a different key.');
      }
      try {
        this.parts.push(this.decoder.decode(opened.plain, { stream: true }));
      } catch (e) {
        return this.fail(peer, 'Decrypted data is not valid UTF-8 text');
      }
      this.chain = await LT.chainStep(this.chain, opened.plain);
      this.receivedBytes += opened.plain.length;
      this.next++;
      if (this.next % ACK_EVERY === 0 || this.next === this.manifest.count) this.send(peer, { t: 'ack', next: this.next });
      this.emit('progress', { next: this.next, count: this.manifest.count, bytes: this.receivedBytes, total: this.manifest.bytes });
      if (this.next === this.manifest.count) await this.finish(peer);
    }

    async finish(peer) {
      clearTimeout(this.stallTimer);
      const d = await LT.finalDigest(this.chain, this.receivedBytes, this.next);
      const dHex = LT.hex(d);
      if (dHex !== this.manifest.digest || this.receivedBytes !== this.manifest.bytes) {
        return this.fail(peer, 'Integrity check failed: the reconstructed content does not match the sender\'s digest');
      }
      try { this.parts.push(this.decoder.decode()); } catch (e) { return this.fail(peer, 'Decrypted data is not valid UTF-8 text'); }
      this.text = this.parts.join('');
      this.parts = [];
      if (this.text.length !== this.manifest.chars) return this.fail(peer, 'Character count does not match the sender');
      this.done = true;
      this.send(peer, { t: 'done', ok: true, digest: dHex });
      this.emit('done', { digest: dHex, text: this.text, manifest: this.manifest });
    }

    /** Ends the connection and drops key material. Keeps nothing unless the transfer completed and keepText is true. */
    destroy(notify, keepText) {
      if (this.destroyed) return;
      clearTimeout(this.stallTimer);
      clearTimeout(this.connectTimer);
      if (notify && this.peer) this.send(this.peer, { t: 'bye' });
      if (this.peer) { const p = this.peer; setTimeout(() => p.close(), notify ? 150 : 0); }
      this.destroyed = true;
      this.peer = null;
      this.sess = null;
      this.parts = [];
      if (!keepText) this.text = null;
    }
  }

  global.PW = { Sender, Receiver, describeCandidate };
})(typeof window !== 'undefined' ? window : globalThis);
