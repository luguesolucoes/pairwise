/* Pairwise UI. Wires the DOM to LT (core) and PW (transport). */
(function () {
  'use strict';
  const LT = window.LT, PW = window.PW;
  const $ = (id) => document.getElementById(id);
  const LARGE_CHARS = 1000000;
  const MAX_LINE_DISPLAY = 2000;
  const nf = new Intl.NumberFormat('en-US');
  const TEST = /[?&]test=1\b/.test(location.search);

  // ---------------------------------------------------------------- helpers
  function fmtBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KiB';
    if (n < 1073741824) return (n / 1048576).toFixed(n < 10485760 ? 2 : 1) + ' MiB';
    return (n / 1073741824).toFixed(2) + ' GiB';
  }
  function fmtRate(bytes, ms) { return ms > 250 ? fmtBytes(Math.round(bytes / (ms / 1000))) + '/s' : '–'; }
  function groupHex(h) { return h.slice(0, 32).replace(/(.{4})/g, '$1 ').trim() + ' …'; }
  function clock(ms) {
    const s = Math.max(0, Math.ceil(ms / 1000));
    return Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0');
  }
  function log(msg) {
    const li = document.createElement('li');
    li.dataset.t = new Date().toLocaleTimeString([], { hour12: false });
    li.textContent = msg;
    const ul = $('log');
    ul.appendChild(li);
    while (ul.children.length > 300) ul.removeChild(ul.firstChild);
    ul.scrollTop = ul.scrollHeight;
  }
  let toastTimer;
  function toast(msg) {
    let el = document.querySelector('.toast');
    if (!el) { el = document.createElement('div'); el.className = 'toast'; el.setAttribute('role', 'status'); document.body.appendChild(el); }
    el.textContent = msg;
    el.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { el.hidden = true; }, 2600);
  }
  function setChip(el, text, kind) { el.textContent = text; el.className = 'chip' + (kind ? ' ' + kind : ''); }
  function errMsg(e) { return e && e.message ? e.message : String(e); }
  function relays() {
    const m = TEST && /[?&]relay=([^&]+)/.exec(location.search);
    if (m) return [{ url: decodeURIComponent(m[1]), label: 'test relay' }];
    return PWR.DEFAULT_RELAYS;
  }
  function iceServers() {
    const list = [];
    if ($('use-stun').checked) list.push({ urls: 'stun:stun.l.google.com:19302' });
    const url = $('turn-url').value.trim();
    if (url) {
      if (!/^turns?:/i.test(url)) throw new Error('TURN URL must start with turn: or turns:');
      list.push({ urls: url, username: $('turn-user').value, credential: $('turn-pass').value });
    }
    return list;
  }

  async function copyText(text, label) {
    try {
      await navigator.clipboard.writeText(text);
      toast((label || 'Text') + ' copied');
      return true;
    } catch (e) {
      if (text.length > 20000000) { toast('Copy was blocked. Use Download instead.'); return false; }
      const ta = document.createElement('textarea');
      ta.value = text; ta.setAttribute('readonly', ''); ta.style.position = 'fixed'; ta.style.opacity = '0';
      document.body.appendChild(ta); ta.select();
      let ok = false;
      try { ok = document.execCommand('copy'); } catch (e2) { ok = false; }
      ta.remove();
      toast(ok ? (label || 'Text') + ' copied' : 'Copy was blocked by the browser. Select the text manually.');
      return ok;
    }
  }

  // ----------------------------------------------------------- QR drawing
  function drawQR(canvas, text) {
    const ecc = text.length > 600 ? 'L' : 'M';
    const qr = window.qrcode(0, ecc);
    qr.addData(text, 'Byte');
    qr.make();
    const n = qr.getModuleCount(), quiet = 4, total = n + quiet * 2;
    const scale = Math.max(2, Math.floor(640 / total));
    canvas.width = canvas.height = total * scale;
    const ctx = canvas.getContext('2d');
    ctx.fillStyle = '#ffffff'; ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = '#000000';
    for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) {
      if (qr.isDark(r, c)) ctx.fillRect((c + quiet) * scale, (r + quiet) * scale, scale, scale);
    }
    return n;
  }

  // ---------------------------------------------------------- QR scanning
  const scanner = {
    stream: null, raf: 0, detector: null, resolve: null,
    async open(title) {
      $('scan-title').textContent = title;
      $('scan-status').textContent = 'Starting camera…';
      const dlg = $('scan-dialog');
      if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) throw new Error('This browser cannot use the camera here. Paste the code instead.');
      dlg.showModal();
      return new Promise(async (resolve) => {
        this.resolve = resolve;
        try {
          this.stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment', width: { ideal: 1280 }, height: { ideal: 960 } }, audio: false });
        } catch (e) {
          $('scan-status').textContent = 'Camera unavailable: ' + errMsg(e) + '. Paste the code instead.';
          return;
        }
        const v = $('scan-video');
        v.srcObject = this.stream;
        try { await v.play(); } catch (e) { /* autoplay with muted should work */ }
        $('scan-status').textContent = 'Looking for a QR code…';
        if ('BarcodeDetector' in window) {
          try { this.detector = new window.BarcodeDetector({ formats: ['qr_code'] }); } catch (e) { this.detector = null; }
        }
        this.loop();
      });
    },
    async loop() {
      const v = $('scan-video'), c = $('scan-canvas');
      if (!this.stream) return;
      if (v.readyState >= 2 && v.videoWidth) {
        let text = null;
        try {
          if (this.detector) {
            const codes = await this.detector.detect(v);
            if (codes.length) text = codes[0].rawValue;
          } else {
            const w = Math.min(960, v.videoWidth), h = Math.round(v.videoHeight * (w / v.videoWidth));
            c.width = w; c.height = h;
            const ctx = c.getContext('2d', { willReadFrequently: true });
            ctx.drawImage(v, 0, 0, w, h);
            const img = ctx.getImageData(0, 0, w, h);
            const r = window.jsQR(img.data, w, h, { inversionAttempts: 'dontInvert' });
            if (r) text = r.data;
          }
        } catch (e) { /* keep scanning */ }
        if (text) { this.close(text); return; }
      }
      this.raf = setTimeout(() => this.loop(), 120);
    },
    close(result) {
      clearTimeout(this.raf);
      if (this.stream) { this.stream.getTracks().forEach((t) => t.stop()); this.stream = null; }
      $('scan-video').srcObject = null;
      const dlg = $('scan-dialog');
      if (dlg.open) dlg.close();
      const r = this.resolve; this.resolve = null;
      if (r) r(result || null);
    }
  };
  $('btn-scan-close').addEventListener('click', () => scanner.close(null));
  $('scan-dialog').addEventListener('cancel', (e) => { e.preventDefault(); scanner.close(null); });

  // ---------------------------------------------------- virtualized viewer
  const MAX_SCROLL_PX = 8000000; // stay under browser element-height limits
  class VirtualView {
    constructor(root) {
      this.root = root;
      root.innerHTML = '';
      this.scroll = document.createElement('div'); this.scroll.className = 'vv-scroll'; this.scroll.tabIndex = 0;
      this.scroll.setAttribute('role', 'region'); this.scroll.setAttribute('aria-label', 'Text viewer');
      this.spacer = document.createElement('div'); this.spacer.className = 'vv-spacer';
      this.rows = document.createElement('div'); this.rows.className = 'vv-rows';
      this.scroll.append(this.spacer, this.rows);
      root.appendChild(this.scroll);
      this.text = ''; this.starts = new Uint32Array(1); this.n = 0;
      this.lh = 18; this.pending = false;
      this.scroll.addEventListener('scroll', () => this.schedule(), { passive: true });
      if ('ResizeObserver' in window) new ResizeObserver(() => this.schedule()).observe(this.scroll);
    }
    setText(text) {
      this.text = text || '';
      this.starts = LT.lineIndex(this.text);
      this.n = this.text.length ? this.starts.length : 0;
      const cs = getComputedStyle(document.documentElement).getPropertyValue('--lh');
      this.lh = parseFloat(cs) || 18;
      this.realH = this.n * this.lh;
      this.virtH = Math.min(this.realH, MAX_SCROLL_PX);
      this.spacer.style.height = this.virtH + 'px';
      this.scroll.scrollTop = 0;
      this.render();
    }
    clear() { this.setText(''); }
    schedule() { if (!this.pending) { this.pending = true; requestAnimationFrame(() => { this.pending = false; this.render(); }); } }
    line(i) {
      const s = this.starts[i];
      let e = i + 1 < this.n ? this.starts[i + 1] - 1 : this.text.length;
      if (e > s && this.text.charCodeAt(e - 1) === 13) e--;
      return [s, e];
    }
    render() {
      const viewH = this.scroll.clientHeight || 300;
      const st = this.scroll.scrollTop;
      let real = st;
      if (this.virtH < this.realH) {
        const maxV = Math.max(1, this.virtH - viewH), maxR = Math.max(0, this.realH - viewH);
        real = (st / maxV) * maxR;
      }
      const first = Math.max(0, Math.floor(real / this.lh));
      const offset = real - first * this.lh;
      const count = Math.min(this.n - first, Math.ceil(viewH / this.lh) + 2);
      const frag = document.createDocumentFragment();
      const digits = String(this.n).length;
      for (let k = 0; k < count; k++) {
        const i = first + k;
        const [s, e] = this.line(i);
        const row = document.createElement('div'); row.className = 'vv-row';
        const num = document.createElement('span'); num.className = 'vv-num'; num.style.minWidth = (digits + 2) + 'ch'; num.textContent = String(i + 1);
        const txt = document.createElement('span'); txt.className = 'vv-txt';
        if (e - s > MAX_LINE_DISPLAY) {
          txt.textContent = this.text.substring(s, s + MAX_LINE_DISPLAY);
          const more = document.createElement('span'); more.className = 'vv-more';
          more.textContent = ' … +' + nf.format(e - s - MAX_LINE_DISPLAY) + ' more characters on this line';
          txt.appendChild(more);
        } else {
          txt.textContent = this.text.substring(s, e);
        }
        row.append(num, txt);
        frag.appendChild(row);
      }
      this.rows.replaceChildren(frag);
      this.rows.style.transform = 'translateY(' + (st - offset) + 'px)';
    }
  }

  // ---------------------------------------------------------------- tabs
  function showTab(which) {
    const send = which === 'send';
    $('tab-send').setAttribute('aria-selected', String(send));
    $('tab-recv').setAttribute('aria-selected', String(!send));
    $('view-send').hidden = !send;
    $('view-recv').hidden = send;
  }
  $('tab-send').addEventListener('click', () => showTab('send'));
  $('tab-recv').addEventListener('click', () => showTab('recv'));

  // ======================================================== SEND side
  const input = $('input');
  const bigView = new VirtualView($('bigview'));
  let bigText = null;        // set when content is too large for the textarea
  let sender = null;
  let sendSignal = null;     // relay listener for automatic pairing
  let currentOfferTag = '';
  let sendExpiry = 0, sendTimer = 0, sendStart = 0;
  let statsTimer = 0;

  function currentText() { return bigText !== null ? bigText : input.value; }

  function updateStats() {
    const t = currentText();
    const bytes = LT.utf8Length(t);
    const chunks = Math.ceil(bytes / LT.CHUNK_BYTES);
    const wire = bytes + chunks * (LT.GCM_TAG + LT.FRAME_HEADER);
    $('st-chars').textContent = nf.format(t.length);
    $('st-lines').textContent = nf.format(LT.countLines(t));
    $('st-bytes').textContent = fmtBytes(bytes);
    $('st-wire').textContent = fmtBytes(wire);
    $('st-chunks').textContent = nf.format(chunks);
    const bad = LT.countUnpairedSurrogates(t);
    const w = $('surrogate-warning');
    w.hidden = bad === 0;
    if (bad) w.textContent = 'This text contains ' + nf.format(bad) + ' broken Unicode character' + (bad === 1 ? '' : 's') + ' (unpaired UTF-16 surrogates). UTF-8 cannot represent them, so each will arrive as the replacement character U+FFFD. Everything else transfers exactly.';
    $('btn-prepare').disabled = t.length === 0 || !!sender;
  }
  function scheduleStats() { clearTimeout(statsTimer); statsTimer = setTimeout(updateStats, input.value.length > 200000 ? 400 : 120); }

  function setBig(text) {
    bigText = text;
    input.value = '';
    input.hidden = true;
    $('bigview-wrap').hidden = false;
    bigView.setText(text);
    updateStats();
    log('Loaded ' + nf.format(text.length) + ' characters into the exact view' + (text.indexOf('\r') !== -1 ? ' (CR/CRLF line endings preserved)' : ''));
  }
  function setSmall(text) {
    bigText = null;
    bigView.clear();
    $('bigview-wrap').hidden = true;
    input.hidden = false;
    input.value = text;
    updateStats();
  }
  // A textarea normalizes CR and CRLF line endings to LF, so text containing CR is kept
  // in the exact (read-only) view instead. Large text goes there too for speed.
  function needsExactView(text) { return text.length > LARGE_CHARS || text.indexOf('\r') !== -1; }
  function loadText(text) { if (needsExactView(text)) setBig(text); else setSmall(text); }

  input.addEventListener('input', scheduleStats);
  input.addEventListener('paste', (e) => {
    if (input.readOnly) return;
    const cd = e.clipboardData;
    if (!cd) return;
    const t = cd.getData('text/plain');
    if (typeof t !== 'string') return;
    if (t.length + input.value.length > LARGE_CHARS || t.indexOf('\r') !== -1) {
      e.preventDefault();
      const v = input.value, a = input.selectionStart, b = input.selectionEnd;
      setBig(v.slice(0, a) + t + v.slice(b));
    }
  });
  $('bigview').addEventListener('paste', (e) => { e.preventDefault(); toast('Large text is read-only. Choose Clear before pasting new content.'); });

  $('btn-paste').addEventListener('click', async () => {
    if (sender) return;
    if (!navigator.clipboard || !navigator.clipboard.readText) { toast('This browser blocks clipboard reading. Click the text area and press Ctrl+V or ⌘V.'); input.focus(); return; }
    try {
      const t = await navigator.clipboard.readText();
      if (!t) { toast('The clipboard has no text'); return; }
      loadText(bigText !== null ? bigText + t : input.value + t);
    } catch (e) {
      toast('Clipboard access was refused. Click the text area and press Ctrl+V or ⌘V.');
      input.focus();
    }
  });
  $('file-input').addEventListener('change', async (e) => {
    const f = e.target.files && e.target.files[0];
    e.target.value = '';
    if (!f || sender) return;
    try {
      const t = await f.text();
      loadText(t);
      log('Opened file ' + f.name + ' (' + fmtBytes(f.size) + ')');
    } catch (err) { toast('Could not read the file: ' + errMsg(err)); }
  });
  $('compose').addEventListener('dragover', (e) => { if (!sender) e.preventDefault(); });
  $('compose').addEventListener('drop', async (e) => {
    const f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
    if (!f || sender) return;
    e.preventDefault();
    try { loadText(await f.text()); log('Opened dropped file ' + f.name); } catch (err) { toast('Could not read the file'); }
  });
  $('btn-clear').addEventListener('click', () => { if (sender) { toast('End the session first'); return; } setSmall(''); input.focus(); });

  function lockEditor(locked) {
    input.readOnly = locked;
    $('btn-paste').disabled = locked;
    $('btn-clear').disabled = locked;
    $('file-input').disabled = locked;
    $('ttl').disabled = locked; $('use-stun').disabled = locked; $('use-relay').disabled = locked;
    ['turn-url', 'turn-user', 'turn-pass'].forEach((id) => { $(id).disabled = locked; });
  }

  let prepareAbort = null;
  $('btn-prepare').addEventListener('click', async () => {
    if (sender) return;
    const text = currentText();
    if (!text.length) return;
    let ice;
    try { ice = iceServers(); } catch (e) { toast(errMsg(e)); return; }
    lockEditor(true);
    $('btn-prepare').disabled = true;
    prepareAbort = new AbortController();
    const t0 = performance.now();
    try {
      const manifest = await LT.prepare(text, {
        signal: prepareAbort.signal,
        onProgress: (p) => { $('prepare-status').textContent = 'Computing integrity digest… ' + Math.round(p * 100) + '%'; }
      });
      log('Prepared ' + nf.format(manifest.count) + ' chunks (' + fmtBytes(manifest.totalBytes) + ') in ' + Math.round(performance.now() - t0) + ' ms');
      const sess = await LT.newSession();
      const ttlMin = parseInt($('ttl').value, 10) || 15;
      sendExpiry = Date.now() + ttlMin * 60000;
      sender = new PW.Sender({ text, manifest, sess, iceServers: ice, expiresAt: sendExpiry, onEvent: onSenderEvent });
      if ($('use-relay').checked) {
        sendSignal = new PWR.Signal(sess, relays(), onSignalEvent);
        sendSignal.listen(onRelayAnswer);
        await sendSignal.start();
        $('manual-pair').open = false;
      } else {
        $('manual-pair').open = true;
      }
      setAutoStatus();
      $('prepare-status').textContent = 'Gathering network candidates…';
      if (!ice.length) log('No STUN or TURN configured: only local-network connections will work');
      await showOffer();
      $('prepare-status').textContent = '';
      $('send-digest').textContent = groupHex(LT.hex(manifest.digest));
      $('send-digest').title = LT.hex(manifest.digest);
      $('send-pair').hidden = false;
      $('send-progress').hidden = true;
      $('send-result').hidden = true;
      startSendTimer();
      $('send-pair').scrollIntoView({ block: 'start', behavior: 'smooth' });
    } catch (e) {
      $('prepare-status').textContent = '';
      if (!(e && e.name === 'AbortError')) toast('Could not prepare the transfer: ' + errMsg(e));
      log('Prepare failed: ' + errMsg(e));
      endSendSession(false);
    }
  });

  function setAutoStatus(text) {
    const el = $('auto-status');
    if (text) { el.textContent = text; return; }
    if (!sendSignal) { el.textContent = 'Automatic pairing is off. Open Pair manually instead below.'; return; }
    el.textContent = 'Waiting for the other device to open the link…';
  }

  function onSignalEvent(type, data) {
    if (type === 'log') log(data);
    else if (type === 'status' && sendSignal && data.open === 0 && data.failed === data.total) {
      setAutoStatus('No pairing relay is reachable from this network. Use Pair manually instead.');
      $('manual-pair').open = true;
    }
  }

  async function onRelayAnswer(text) {
    if (!sender || !sender.peer) return;
    let msg;
    try { msg = JSON.parse(text); } catch (e) { return; }
    if (!msg || typeof msg.a !== 'string' || msg.f !== currentOfferTag) return; // reply to an older code
    if (sender.peer.pc.signalingState !== 'have-local-offer') return;          // already paired
    log('Reply received through the pairing relay');
    setAutoStatus('The other device answered. Connecting…');
    await applyAnswer(msg.a);
  }

  async function showOffer() {
    const frag0 = await sender.createOffer();
    const frag = frag0 + (sendSignal ? '!a' : '');
    currentOfferTag = await LT.offerTag(frag0.split('!')[3]);
    const base = location.href.split('#')[0].split('?')[0];
    const link = base + '#' + frag;
    const modules = drawQR($('send-qr'), link);
    $('send-link').value = link;
    $('answer-input').value = '';
    $('answer-error').textContent = '';
    log('Pairing code ready (' + link.length + ' characters, QR ' + modules + '×' + modules + ' modules)');
  }

  function startSendTimer() {
    clearInterval(sendTimer);
    const tick = () => {
      const left = sendExpiry - Date.now();
      setChip($('send-expiry'), 'Expires in ' + clock(left), left < 60000 ? 'warn' : '');
      if (left <= 0) { log('Session expired; keys discarded'); endSendSession(true, 'Session expired. The key has been discarded.'); }
    };
    tick();
    sendTimer = setInterval(tick, 1000);
  }

  $('btn-copy-link').addEventListener('click', () => copyText($('send-link').value, 'Link'));
  $('btn-connect').addEventListener('click', () => applyAnswer($('answer-input').value));
  $('btn-scan-answer').addEventListener('click', async () => {
    try {
      const text = await scanner.open('Scan the answer QR on the receiving device');
      if (text) { $('answer-input').value = text; applyAnswer(text); }
    } catch (e) { toast(errMsg(e)); }
  });

  async function applyAnswer(code) {
    if (!sender) return;
    $('answer-error').textContent = '';
    try {
      await sender.acceptAnswer(code);
      $('send-progress').hidden = false;
      $('send-resume').hidden = true;
      setChip($('send-state'), 'connecting', 'live');
    } catch (e) {
      $('answer-error').textContent = errMsg(e);
      $('answer-error').style.color = 'var(--bad)';
    }
  }

  function onSenderEvent(type, data) {
    if (type === 'log') log(data);
    else if (type === 'state') {
      setChip($('send-state'), data, 'live');
      if (data === 'sending') { sendStart = performance.now(); $('send-pair').hidden = true; $('send-resume').hidden = true; }
    } else if (type === 'progress') {
      const pSent = data.count ? data.sent / data.count : 1, pAck = data.count ? data.acked / data.count : 1;
      $('send-bar-sent').style.width = (pSent * 100).toFixed(2) + '%';
      $('send-bar-ack').style.width = (pAck * 100).toFixed(2) + '%';
      $('sp-sent').textContent = fmtBytes(Math.round(data.bytes * pSent));
      $('sp-ack').textContent = fmtBytes(Math.round(data.bytes * pAck));
      $('sp-rate').textContent = fmtRate(data.bytes * pAck, performance.now() - sendStart);
    } else if (type === 'done') {
      setChip($('send-state'), 'verified', 'ok');
      const r = $('send-result');
      r.className = 'notice ok'; r.hidden = false;
      r.textContent = 'Delivered and verified. The recipient rebuilt the text and its SHA-256 integrity digest matches: ' + groupHex(data.digest);
      log('Recipient confirmed the integrity digest');
      if (sendSignal) { sendSignal.close(); sendSignal = null; }
    } else if (type === 'disconnected') {
      if (!sender || sender.verified) return;
      setChip($('send-state'), 'disconnected', 'warn');
      $('send-resume').hidden = false;
      log('Connection lost' + (data && data.reason ? ' (' + data.reason + ')' : ''));
    } else if (type === 'error') {
      setChip($('send-state'), 'error', 'bad');
      const r = $('send-result');
      r.className = 'notice bad'; r.hidden = false; r.textContent = data;
      $('send-resume').hidden = false;
      log('Error: ' + data);
    } else if (type === 'remote-bye') {
      const verified = sender && sender.verified;
      endSendSession(false, verified ? null : 'The recipient ended the session.');
      setChip($('send-state'), verified ? 'verified · session closed' : 'closed', verified ? 'ok' : 'warn');
    }
  }

  $('btn-new-code').addEventListener('click', async () => {
    if (!sender) return;
    try {
      await showOffer();
      setAutoStatus();
      $('send-pair').hidden = false;
      $('send-resume').hidden = true;
      $('send-result').hidden = true;
      $('send-pair').scrollIntoView({ block: 'start', behavior: 'smooth' });
    } catch (e) { toast('Could not create a new code: ' + errMsg(e)); }
  });

  function endSendSession(notify, message) {
    if (prepareAbort) prepareAbort.abort();
    if (sendSignal) { sendSignal.close(); sendSignal = null; }
    if (sender) { sender.destroy(notify); sender = null; log('Send session ended; key material discarded'); }
    clearInterval(sendTimer);
    const c = $('send-qr'); c.getContext('2d').clearRect(0, 0, c.width, c.height);
    $('send-link').value = '';
    $('answer-input').value = '';
    $('send-pair').hidden = true;
    $('send-resume').hidden = true;
    lockEditor(false);
    updateStats();
    if (message) {
      $('send-progress').hidden = false;
      const r = $('send-result'); r.className = 'notice warn'; r.hidden = false; r.textContent = message;
    }
  }
  $('btn-send-end').addEventListener('click', () => {
    const wasActive = !!sender;
    endSendSession(true);
    if (wasActive) { setChip($('send-state'), 'ended', ''); toast('Session ended'); }
  });

  // ===================================================== RECEIVE side
  const recvView = new VirtualView($('recvview'));
  let receiver = null, receivedText = null, recvExpiry = 0, recvTimer = 0, recvStart = 0;
  let recvSignal = null;
  function stopRecvSignal() { if (recvSignal) { recvSignal.close(); recvSignal = null; } }

  function ensureReceiver() {
    if (!receiver) {
      let ice = [];
      try { ice = iceServers(); } catch (e) { ice = []; }
      receiver = new PW.Receiver({ iceServers: ice, onEvent: onReceiverEvent });
    }
    return receiver;
  }

  async function startReceive(text) {
    $('offer-error').textContent = '';
    let offer;
    try { offer = LT.parseOffer(text); } catch (e) { $('offer-error').textContent = errMsg(e); $('offer-error').style.color = 'var(--bad)'; return; }
    showTab('recv');
    $('answer-out').value = '';
    $('recv-connect').hidden = true;
    $('recv-answer').hidden = false;
    $('recv-issue').hidden = true;
    setChip($('recv-state'), 'connecting', 'live');
    $('recv-manual').open = !offer.auto;
    $('recv-auto-status').textContent = offer.auto
      ? 'Connecting to the sender. The text is decrypted on this device as soon as it arrives.'
      : 'The sender turned off automatic pairing. Open Pair manually and show the reply code to the sender.';
    try {
      const r = ensureReceiver();
      log(r.sess ? 'New code for the same session: reconnecting to resume' : 'Sender code accepted; preparing the connection');
      const answer = await r.acceptOffer(offer);
      drawQR($('recv-qr'), answer);
      $('answer-out').value = answer;
      if (offer.auto) {
        stopRecvSignal();
        recvSignal = new PWR.Signal(r.sess, relays(), (type, data) => {
          if (type === 'log') log(data);
          else if (type === 'status' && data.open === 0 && data.failed === data.total) {
            $('recv-auto-status').textContent = 'No pairing relay is reachable from this network. Open Pair manually and show the reply code to the sender.';
            $('recv-manual').open = true;
          }
        });
        await recvSignal.start();
        const tag = await LT.offerTag(offer.compact);
        await recvSignal.publishRepeatedly(JSON.stringify({ a: answer, f: tag }), 180000);
        log('Sent the encrypted connection reply through the pairing relays');
      } else {
        log('Reply ready (' + answer.length + ' characters). Show it to the sending device.');
      }
    } catch (e) {
      $('recv-answer').hidden = true;
      $('recv-connect').hidden = false;
      $('offer-error').textContent = errMsg(e);
      $('offer-error').style.color = 'var(--bad)';
      log('Pairing failed: ' + errMsg(e));
    }
  }

  $('btn-offer-go').addEventListener('click', () => startReceive($('offer-input').value));
  $('offer-input').addEventListener('keydown', (e) => { if (e.key === 'Enter') startReceive($('offer-input').value); });
  $('btn-scan-offer').addEventListener('click', async () => {
    try {
      const text = await scanner.open("Scan the code on the sending device");
      if (text) startReceive(text);
    } catch (e) { toast(errMsg(e)); }
  });
  $('btn-copy-answer').addEventListener('click', () => copyText($('answer-out').value, 'Reply code'));
  $('btn-recv-cancel').addEventListener('click', () => resetReceive(true));

  function startRecvTimer() {
    clearInterval(recvTimer);
    const tick = () => {
      const left = recvExpiry - Date.now();
      setChip($('recv-expiry'), 'Expires in ' + clock(left), left < 60000 ? 'warn' : '');
      if (left <= 0) {
        clearInterval(recvTimer);
        if (receiver && !receiver.done) { log('Session expired before completion; partial data discarded'); resetReceive(false, 'The session expired before the transfer finished. Partial data was discarded.'); }
      }
    };
    tick();
    recvTimer = setInterval(tick, 1000);
  }

  function onReceiverEvent(type, data) {
    if (type === 'log') log(data);
    else if (type === 'state') {
      if (data === 'connected' || data === 'receiving') {
        stopRecvSignal();
        $('recv-answer').hidden = true;
        $('recv-progress').hidden = false;
        $('recv-issue').hidden = true;
        if (!recvStart) recvStart = performance.now();
      }
      setChip($('recv-state'), data, 'live');
    } else if (type === 'manifest') {
      $('rp-total').textContent = fmtBytes(data.bytes);
      $('rp-count').textContent = nf.format(data.count);
      if (data.exp && Number.isFinite(data.exp)) { recvExpiry = data.exp; startRecvTimer(); }
      if (data.unpaired) log('Sender reports ' + data.unpaired + ' unpaired surrogates replaced by U+FFFD');
    } else if (type === 'progress') {
      const p = data.count ? data.next / data.count : 1;
      $('recv-bar').style.width = (p * 100).toFixed(2) + '%';
      $('rp-bytes').textContent = fmtBytes(data.bytes);
      $('rp-chunk').textContent = nf.format(data.next);
      $('rp-rate').textContent = fmtRate(data.bytes, performance.now() - recvStart);
    } else if (type === 'done') {
      receivedText = data.text;
      clearInterval(recvTimer);
      setChip($('recv-expiry'), 'complete', 'ok');
      $('recv-progress').hidden = true;
      $('recv-result').hidden = false;
      $('recv-verified').textContent = 'Verified. All ' + nf.format(data.manifest.count) + ' chunks authenticated and the SHA-256 integrity digest matches the sender: ' + groupHex(data.digest);
      $('rr-chars').textContent = nf.format(receivedText.length);
      $('rr-lines').textContent = nf.format(data.manifest.lines);
      $('rr-bytes').textContent = fmtBytes(data.manifest.bytes);
      recvView.setText(receivedText);
      if (!$('save-name').value) $('save-name').value = defaultSaveName();
      stopRecvSignal();
      log('Transfer complete and verified');
      // Close the connection and drop the key; keep only the decrypted text.
      setTimeout(() => { if (receiver) { receiver.destroy(true, true); receiver = null; log('Connection closed; key material discarded'); } }, 400);
    } else if (type === 'disconnected' || type === 'stalled') {
      if (!receiver || receiver.done) return;
      const issue = $('recv-issue');
      issue.hidden = false;
      issue.textContent = type === 'stalled'
        ? 'No data for 30 seconds. If the sender is still connected, wait; otherwise ask for a new code and scan it here to resume.'
        : 'Connection lost. Ask the sender to create a new pairing code, then scan or paste it here. The transfer resumes where it stopped.';
      $('recv-connect').hidden = false;
      log(type === 'stalled' ? 'No data received for 30 seconds' : 'Connection lost');
    } else if (type === 'error') {
      const issue = $('recv-issue');
      issue.hidden = false; issue.className = 'notice bad'; issue.textContent = data;
      $('recv-progress').hidden = false;
      $('recv-connect').hidden = false;
      log('Error: ' + data);
    } else if (type === 'remote-bye') {
      if (receiver && !receiver.done) resetReceive(false, 'The sender ended the session before the transfer finished.');
    }
  }

  function resetReceive(notify, message) {
    stopRecvSignal();
    if (receiver) { receiver.destroy(notify, false); receiver = null; }
    clearInterval(recvTimer);
    recvExpiry = 0; recvStart = 0;
    $('recv-answer').hidden = true;
    $('recv-progress').hidden = true;
    $('recv-connect').hidden = false;
    $('answer-out').value = '';
    $('offer-input').value = '';
    const c = $('recv-qr'); c.getContext('2d').clearRect(0, 0, c.width, c.height);
    $('recv-bar').style.width = '0%';
    if (message) { $('offer-error').textContent = message; $('offer-error').style.color = 'var(--warn)'; }
  }

  $('btn-copy-all').addEventListener('click', () => { if (receivedText !== null) copyText(receivedText, nf.format(receivedText.length) + ' characters'); });
  function defaultSaveName() { return 'pairwise-' + new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19).replace('T', '_'); }
  function cleanFileName(name) {
    const n = String(name || '').replace(/[\u0000-\u001f\u007f<>:"/\\|?*]/g, '_').replace(/^[.\s]+|[.\s]+$/g, '').slice(0, 200);
    return n || defaultSaveName();
  }
  $('btn-download').addEventListener('click', async () => {
    if (receivedText === null) return;
    const name = cleanFileName($('save-name').value);
    $('save-name').value = name;
    // Raw bytes with a generic type, so the browser keeps the name exactly as typed
    // (no .txt appended when there is no extension).
    const blob = new Blob([receivedText], { type: 'application/octet-stream' });
    if (typeof window.showSaveFilePicker === 'function') {
      try {
        const handle = await window.showSaveFilePicker({ suggestedName: name });
        const w = await handle.createWritable();
        await w.write(blob);
        await w.close();
        toast('Saved ' + handle.name);
        log('Saved ' + fmtBytes(blob.size) + ' to ' + handle.name);
        return;
      } catch (e) {
        if (e && e.name === 'AbortError') return; // user cancelled the dialog
        // Otherwise fall back to a regular download.
      }
    }
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 60000);
    log('Downloaded ' + fmtBytes(blob.size) + ' as ' + name);
  });
  $('btn-recv-clear').addEventListener('click', () => {
    receivedText = null;
    recvView.clear();
    $('save-name').value = '';
    $('recv-result').hidden = true;
    resetReceive(true);
    $('offer-error').textContent = '';
    log('Received text cleared from this page');
  });

  // ============================================================ startup
  function checkEnvironment() {
    const missing = [];
    if (!window.isSecureContext) missing.push('a secure (HTTPS) page');
    if (!window.crypto || !window.crypto.subtle) missing.push('the Web Crypto API');
    if (typeof RTCPeerConnection === 'undefined') missing.push('WebRTC');
    if (typeof TextEncoder === 'undefined' || !TextEncoder.prototype.encodeInto) missing.push('TextEncoder.encodeInto');
    if (missing.length) {
      const w = $('env-warning');
      w.hidden = false;
      w.textContent = 'This browser or page context is missing ' + missing.join(', ') + '. Pairwise cannot run here. Open it over HTTPS (or localhost) in a current Chrome, Edge, Firefox or Safari.';
      $('btn-prepare').disabled = true;
      return false;
    }
    if (location.protocol === 'file:') {
      const w = $('env-warning');
      w.hidden = false; w.className = 'notice warn';
      w.textContent = 'Opened from a local file: the QR link will not open on another device. Host the page over HTTPS, or open this same file on the other device and use Scan sender\'s code.';
    }
    return true;
  }

  const envOk = checkEnvironment();
  updateStats();
  if (location.hash.startsWith('#' + LT.PROTO + '!') || location.hash.startsWith('#' + encodeURIComponent(LT.PROTO + '!'))) {
    const frag = location.hash;
    // Remove the key from the address bar and the history entry immediately.
    try { history.replaceState(null, '', location.pathname + location.search); } catch (e) { /* ignore */ }
    showTab('recv');
    if (envOk) startReceive(frag);
  }
  window.addEventListener('beforeunload', () => { if (sender) sender.destroy(true); if (receiver) receiver.destroy(true, false); });

  if (TEST) {
    window.__pw = {
      received: () => receivedText,
      senderText: () => currentText(),
      loadText,
      isBig: () => bigText !== null,
      dropLink: () => { if (sender && sender.peer && sender.peer.dc) sender.peer.dc.close(); }
    };
  }
})();
