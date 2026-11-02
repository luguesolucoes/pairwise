/* Pairwise UI. One side encrypts and pairs; the other retrieves and decrypts.
 * Wires the DOM to LT (crypto + blob format) and NET (server client). */
(function () {
  'use strict';
  const LT = window.LT, NET = window.NET;
  const $ = (id) => document.getElementById(id);
  const LARGE_CHARS = 1000000;
  const MAX_LINE_DISPLAY = 2000;
  const nf = new Intl.NumberFormat('en-US');
  const TEST = /[?&]test=1\b/.test(location.search);
  let serverLimits = null;

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
    if (s >= 3600) return Math.floor(s / 3600) + 'h ' + Math.floor((s % 3600) / 60) + 'm';
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
    el.textContent = msg; el.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { el.hidden = true; }, 2800);
  }
  function setChip(el, text, kind) { el.textContent = text; el.className = 'chip' + (kind ? ' ' + kind : ''); }
  function errMsg(e) { return e && e.message ? e.message : String(e); }

  async function copyText(text, label) {
    try { await navigator.clipboard.writeText(text); toast((label || 'Text') + ' copied'); return true; }
    catch (e) {
      if (text.length > 20000000) { toast('Copy was blocked. Use Save as file instead.'); return false; }
      const ta = document.createElement('textarea');
      ta.value = text; ta.setAttribute('readonly', ''); ta.style.position = 'fixed'; ta.style.opacity = '0';
      document.body.appendChild(ta); ta.select();
      let ok = false; try { ok = document.execCommand('copy'); } catch (e2) { ok = false; }
      ta.remove();
      toast(ok ? (label || 'Text') + ' copied' : 'Copy was blocked by the browser. Select the text manually.');
      return ok;
    }
  }

  // ----------------------------------------------------------- QR drawing
  function drawQR(canvas, text) {
    const ecc = text.length > 600 ? 'L' : 'M';
    const qr = window.qrcode(0, ecc);
    qr.addData(text, 'Byte'); qr.make();
    const n = qr.getModuleCount(), quiet = 4, total = n + quiet * 2;
    const scale = Math.max(2, Math.floor(640 / total));
    canvas.width = canvas.height = total * scale;
    const ctx = canvas.getContext('2d');
    ctx.fillStyle = '#ffffff'; ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = '#000000';
    for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) if (qr.isDark(r, c)) ctx.fillRect((c + quiet) * scale, (r + quiet) * scale, scale, scale);
    return n;
  }

  // ---------------------------------------------------- virtualized viewer
  const MAX_SCROLL_PX = 8000000;
  class VirtualView {
    constructor(root) {
      this.root = root; root.innerHTML = '';
      this.scroll = document.createElement('div'); this.scroll.className = 'vv-scroll'; this.scroll.tabIndex = 0;
      this.scroll.setAttribute('role', 'region'); this.scroll.setAttribute('aria-label', 'Text viewer');
      this.spacer = document.createElement('div'); this.spacer.className = 'vv-spacer';
      this.rows = document.createElement('div'); this.rows.className = 'vv-rows';
      this.scroll.append(this.spacer, this.rows);
      root.appendChild(this.scroll);
      this.text = ''; this.starts = new Uint32Array(1); this.n = 0; this.lh = 18; this.pending = false;
      this.scroll.addEventListener('scroll', () => this.schedule(), { passive: true });
      if ('ResizeObserver' in window) new ResizeObserver(() => this.schedule()).observe(this.scroll);
    }
    setText(text) {
      this.text = text || '';
      this.starts = LT.lineIndex(this.text);
      this.n = this.text.length ? this.starts.length : 0;
      this.lh = parseFloat(getComputedStyle(document.documentElement).getPropertyValue('--lh')) || 18;
      this.realH = this.n * this.lh;
      this.virtH = Math.min(this.realH, MAX_SCROLL_PX);
      this.spacer.style.height = this.virtH + 'px';
      this.scroll.scrollTop = 0; this.render();
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
        } else txt.textContent = this.text.substring(s, e);
        row.append(num, txt); frag.appendChild(row);
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
  let bigText = null;
  let busy = false;              // encrypting or uploading
  let sendAbort = null;
  let active = null;             // { id, expiresAt } of the uploaded blob
  let expiryTimer = 0;
  let statsTimer = 0;

  function currentText() { return bigText !== null ? bigText : input.value; }
  function wireBytes(bytes) { const chunks = Math.ceil(bytes / LT.CHUNK_BYTES); return LT.MAGIC.length + bytes + chunks * (LT.FRAME_HEADER + LT.GCM_TAG + 4) + 256; }

  function updateStats() {
    const t = currentText();
    const bytes = LT.utf8Length(t);
    const wire = wireBytes(bytes);
    $('st-chars').textContent = nf.format(t.length);
    $('st-lines').textContent = nf.format(LT.countLines(t));
    $('st-bytes').textContent = fmtBytes(bytes);
    $('st-wire').textContent = fmtBytes(wire);
    const bad = LT.countUnpairedSurrogates(t);
    const w = $('surrogate-warning');
    w.hidden = bad === 0;
    if (bad) w.textContent = 'This text contains ' + nf.format(bad) + ' broken Unicode character' + (bad === 1 ? '' : 's') + ' (unpaired UTF-16 surrogates). UTF-8 cannot represent them, so each will arrive as the replacement character U+FFFD. Everything else transfers exactly.';
    const overLimit = serverLimits && wire > serverLimits.maxBytes;
    if (overLimit) { $('ttl-note').textContent = 'Too large: server accepts up to ' + fmtBytes(serverLimits.maxBytes) + '.'; $('ttl-note').style.color = 'var(--bad)'; }
    else if (serverLimits) { $('ttl-note').textContent = 'Up to ' + fmtBytes(serverLimits.maxBytes) + '.'; $('ttl-note').style.color = ''; }
    $('btn-send').disabled = busy || t.length === 0 || !!overLimit;
  }
  function scheduleStats() { clearTimeout(statsTimer); statsTimer = setTimeout(updateStats, input.value.length > 200000 ? 400 : 120); }

  function setBig(text) {
    bigText = text; input.value = ''; input.hidden = true;
    $('bigview-wrap').hidden = false; bigView.setText(text); updateStats();
    log('Loaded ' + nf.format(text.length) + ' characters into the exact view' + (text.indexOf('\r') !== -1 ? ' (CR/CRLF line endings preserved)' : ''));
  }
  function setSmall(text) {
    bigText = null; bigView.clear(); $('bigview-wrap').hidden = true;
    input.hidden = false; input.value = text; updateStats();
  }
  function needsExactView(text) { return text.length > LARGE_CHARS || text.indexOf('\r') !== -1; }
  function loadText(text) { if (needsExactView(text)) setBig(text); else setSmall(text); }

  input.addEventListener('input', scheduleStats);
  input.addEventListener('paste', (e) => {
    if (input.readOnly) return;
    const cd = e.clipboardData; if (!cd) return;
    const t = cd.getData('text/plain'); if (typeof t !== 'string') return;
    if (t.length + input.value.length > LARGE_CHARS || t.indexOf('\r') !== -1) {
      e.preventDefault();
      const v = input.value, a = input.selectionStart, b = input.selectionEnd;
      setBig(v.slice(0, a) + t + v.slice(b));
    }
  });
  $('bigview').addEventListener('paste', (e) => { e.preventDefault(); toast('Large text is read-only. Choose Clear before pasting new content.'); });

  $('btn-paste').addEventListener('click', async () => {
    if (busy) return;
    if (!navigator.clipboard || !navigator.clipboard.readText) { toast('This browser blocks clipboard reading. Click the text area and press Ctrl+V or ⌘V.'); input.focus(); return; }
    try {
      const t = await navigator.clipboard.readText();
      if (!t) { toast('The clipboard has no text'); return; }
      loadText(bigText !== null ? bigText + t : input.value + t);
    } catch (e) { toast('Clipboard access was refused. Click the text area and press Ctrl+V or ⌘V.'); input.focus(); }
  });
  $('file-input').addEventListener('change', async (e) => {
    const f = e.target.files && e.target.files[0]; e.target.value = '';
    if (!f || busy) return;
    try { const t = await f.text(); loadText(t); log('Opened file ' + f.name + ' (' + fmtBytes(f.size) + ')'); }
    catch (err) { toast('Could not read the file: ' + errMsg(err)); }
  });
  $('compose').addEventListener('dragover', (e) => { if (!busy) e.preventDefault(); });
  $('compose').addEventListener('drop', async (e) => {
    const f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
    if (!f || busy) return;
    e.preventDefault();
    try { loadText(await f.text()); log('Opened dropped file ' + f.name); } catch (err) { toast('Could not read the file'); }
  });
  $('btn-clear').addEventListener('click', () => { if (busy) { toast('Cancel the pairing first'); return; } setSmall(''); input.focus(); });

  function lockCompose(locked) {
    input.readOnly = locked;
    ['btn-paste', 'btn-clear', 'file-input', 'ttl', 'once'].forEach((id) => { $(id).disabled = locked; });
  }

  async function buildBlob(sess, text, manifest, opts) {
    const parts = [LT.MAGIC];
    const mframe = await LT.sealFrame(sess, LT.T_MANIFEST, 0, 0, LT.encodeManifest(manifest, opts.expiresAt || 0));
    parts.push(LT.u32be(mframe.length), mframe);
    const buf = new Uint8Array(manifest.chunkBytes);
    for (let i = 0; i < manifest.count; i++) {
      if (opts.signal && opts.signal.aborted) throw new DOMException('Cancelled', 'AbortError');
      const plain = LT.chunkBytesAt(text, manifest, i, buf);
      const frame = await LT.sealFrame(sess, LT.T_DATA, i, manifest.count, plain);
      parts.push(LT.u32be(frame.length), frame);
      if ((i & 31) === 31) { opts.onProgress && opts.onProgress((i + 1) / manifest.count); await Promise.resolve(); }
    }
    opts.onProgress && opts.onProgress(1);
    return new Blob(parts, { type: 'application/octet-stream' });
  }

  function retrieveLink(sess, id) {
    const base = location.href.split('#')[0].split('?')[0];
    return base + '#' + LT.retrieveFragment(sess, id);
  }

  $('btn-send').addEventListener('click', async () => {
    if (busy) return;
    const text = currentText();
    if (!text.length) return;
    busy = true;
    lockCompose(true);
    $('btn-send').disabled = true;
    $('btn-cancel-send').hidden = false;
    $('upload-bar-wrap').hidden = false;
    $('upload-bar').style.width = '0%';
    $('send-result').hidden = true;
    sendAbort = new AbortController();
    const signal = sendAbort.signal;
    const t0 = performance.now();
    try {
      $('send-status').textContent = 'Preparing…';
      const manifest = await LT.prepare(text, { signal, onProgress: (p) => { $('send-status').textContent = 'Computing integrity digest… ' + Math.round(p * 100) + '%'; } });
      const sess = await LT.newSession();
      const ttl = parseInt($('ttl').value, 10) || 900;
      const once = $('once').checked;
      const plannedExpiry = Date.now() + ttl * 1000;

      $('send-status').textContent = 'Encrypting…';
      const blob = await buildBlob(sess, text, manifest, { expiresAt: plannedExpiry, signal, onProgress: (p) => { $('send-status').textContent = 'Encrypting… ' + Math.round(p * 100) + '%'; } });
      log('Encrypted ' + nf.format(manifest.count) + ' chunks (' + fmtBytes(blob.size) + ') in ' + Math.round(performance.now() - t0) + ' ms');

      $('send-status').textContent = 'Pairing…';
      const onWait = (secs) => { $('send-status').textContent = 'Waking the server… ' + secs + 's (free hosts sleep when idle; first use can take up to a minute)'; };
      await NET.wake({ signal, onWait });
      const res = await NET.uploadBlob(blob, { ttl, once, signal, onWait, onProgress: (loaded, total) => {
        $('upload-bar').style.width = (total ? (loaded / total * 100) : 0).toFixed(1) + '%';
        $('send-status').textContent = 'Pairing… ' + fmtBytes(loaded) + ' / ' + fmtBytes(total);
      } });
      log('Paired. Server holds it as id ' + res.id + (once ? ', deletes after first download' : ''));

      active = { id: res.id, expiresAt: res.expiresAt || plannedExpiry };
      const link = retrieveLink(sess, res.id);
      if (TEST) window.__pw.lastLink = link;
      const modules = drawQR($('send-qr'), link);
      $('send-link').value = link;
      $('send-digest').textContent = groupHex(LT.hex(manifest.digest));
      $('send-digest').title = LT.hex(manifest.digest);
      const note = $('send-note');
      note.hidden = false;
      note.textContent = once
        ? 'This link can be opened once. After the first device downloads it, the server deletes it.'
        : 'This link can be opened more than once until it expires.';
      $('send-status').textContent = '';
      $('upload-bar-wrap').hidden = true;
      $('send-result').hidden = false;
      startExpiry();
      $('send-result').scrollIntoView({ block: 'start', behavior: 'smooth' });
      log('QR ready (' + link.length + ' characters, QR ' + modules + '×' + modules + ' modules). You can close this page.');
    } catch (e) {
      $('upload-bar-wrap').hidden = true;
      if (e && e.name === 'AbortError') { $('send-status').textContent = 'Cancelled.'; log('Pairing cancelled'); }
      else { $('send-status').textContent = ''; toast(errMsg(e)); log('Pairing failed: ' + errMsg(e)); }
    } finally {
      busy = false;
      sendAbort = null;
      $('btn-cancel-send').hidden = true;
      lockCompose(false);
      updateStats();
    }
  });

  $('btn-cancel-send').addEventListener('click', () => { if (sendAbort) sendAbort.abort(); });

  function startExpiry() {
    clearInterval(expiryTimer);
    const tick = () => {
      if (!active) return;
      const left = active.expiresAt - Date.now();
      setChip($('send-expiry'), left > 0 ? 'Expires in ' + clock(left) : 'Expired', left < 60000 ? 'warn' : '');
      if (left <= 0) { clearInterval(expiryTimer); log('Link expired on the server'); }
    };
    tick(); expiryTimer = setInterval(tick, 1000);
  }

  $('btn-copy-link').addEventListener('click', () => copyText($('send-link').value, 'Link'));
  $('btn-destroy').addEventListener('click', async () => {
    if (!active) return;
    const id = active.id;
    await NET.destroy(id);
    clearInterval(expiryTimer);
    active = null;
    $('send-result').hidden = true;
    const c = $('send-qr'); c.getContext('2d').clearRect(0, 0, c.width, c.height);
    $('send-link').value = '';
    toast('Deleted from the server');
    log('Deleted blob ' + id + ' from the server');
  });

  // ===================================================== RECEIVE side
  const recvView = new VirtualView($('recvview'));
  let receivedText = null;
  let recvAbort = null;
  let recvBusy = false;

  async function startReceive(text) {
    if (recvBusy) return;
    $('offer-error').textContent = '';
    let link;
    try { link = LT.parseRetrieve(text); } catch (e) { $('offer-error').textContent = errMsg(e); $('offer-error').style.color = 'var(--bad)'; return; }
    showTab('recv');
    recvBusy = true;
    $('recv-connect').hidden = true;
    $('recv-progress').hidden = false;
    $('recv-result').hidden = true;
    $('recv-issue').hidden = true;
    $('recv-bar').style.width = '0%';
    setChip($('recv-state'), 'downloading', 'live');
    recvAbort = new AbortController();
    const signal = recvAbort.signal;
    const t0 = performance.now();

    let sess;
    const splitter = new LT.FrameSplitter();
    let manifest = null, next = 0, chain = new Uint8Array(32), parts = [], recvBytes = 0;
    const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

    async function onChunk(bytes) {
      const frames = splitter.push(bytes);
      for (const f of frames) {
        const hdr = LT.frameHeader(f);
        if (hdr.type === LT.T_MANIFEST) {
          const o = await LT.openFrame(sess, f, 0);
          if (!manifest) {
            manifest = LT.decodeManifest(o.plain);
            $('rp-total').textContent = fmtBytes(manifest.bytes);
            if (manifest.unpaired) log('The text has ' + manifest.unpaired + ' unpaired surrogates, replaced by U+FFFD');
            log('Manifest: ' + nf.format(manifest.count) + ' chunks, ' + fmtBytes(manifest.bytes));
          }
          continue;
        }
        if (!manifest) throw new Error('Encrypted data arrived before the manifest');
        if (hdr.index !== next) throw new Error('Chunk ' + hdr.index + ' out of order (expected ' + next + ')');
        const o = await LT.openFrame(sess, f, manifest.count);
        parts.push(decoder.decode(o.plain, { stream: true }));
        chain = await LT.chainStep(chain, o.plain);
        recvBytes += o.plain.length; next++;
      }
    }

    try {
      sess = await LT.openSession(link.sid, link.key);
      const onWait = (secs) => setChip($('recv-state'), 'waking the server… ' + secs + 's', 'live');
      const meta = await NET.getMeta(link.id, { signal, onWait });
      if (!meta) throw new Error('This transfer no longer exists. It may have expired or already been opened.');
      log('Found it on the server (' + fmtBytes(meta.size) + (meta.once ? ', one-time' : '') + '). Receiving…');
      setChip($('recv-state'), 'downloading & decrypting', 'live');
      await NET.downloadStream(link.id, {
        signal, onWait,
        onChunk: (bytes) => onChunk(bytes),
        onProgress: (loaded, total) => {
          $('recv-bar').style.width = (total ? (loaded / total * 100) : 0).toFixed(1) + '%';
          $('rp-bytes').textContent = fmtBytes(loaded);
          if (total) $('rp-total').textContent = fmtBytes(total);
          $('rp-rate').textContent = fmtRate(loaded, performance.now() - t0);
        }
      });
      splitter.end();
      if (!manifest) throw new Error('The download contained no manifest');
      if (next !== manifest.count) throw new Error('Missing chunks: got ' + next + ' of ' + manifest.count);
      const digest = LT.hex(await LT.finalDigest(chain, recvBytes, next));
      if (recvBytes !== manifest.bytes || digest !== manifest.digest) throw new Error('Integrity check failed: the content does not match the original digest');
      parts.push(decoder.decode());
      const full = parts.join('');
      parts = [];
      if (full.length !== manifest.chars) throw new Error('Character count does not match the original');
      receivedText = full;

      setChip($('recv-state'), 'verified', 'ok');
      $('recv-progress').hidden = true;
      $('recv-result').hidden = false;
      $('recv-verified').textContent = 'Verified. All ' + nf.format(manifest.count) + ' chunks decrypted and the SHA-256 integrity digest matches the original: ' + groupHex(digest);
      $('rr-chars').textContent = nf.format(receivedText.length);
      $('rr-lines').textContent = nf.format(manifest.lines);
      $('rr-bytes').textContent = fmtBytes(manifest.bytes);
      $('save-name').value = defaultSaveName();
      recvView.setText(receivedText);
      log('Transfer complete and verified' + (meta.once ? '; server has deleted its copy' : ''));
    } catch (e) {
      if (e && e.name === 'AbortError') { log('Receive cancelled'); }
      else {
        const issue = $('recv-issue');
        issue.hidden = false; issue.className = 'notice bad';
        issue.textContent = (e && e.name === 'OperationError')
          ? 'Could not decrypt. The link is for a different key, or the stored data was altered.'
          : errMsg(e);
        setChip($('recv-state'), 'failed', 'bad');
        log('Receive failed: ' + errMsg(e));
      }
      $('recv-connect').hidden = false;
    } finally {
      recvBusy = false; recvAbort = null;
    }
  }

  $('btn-offer-go').addEventListener('click', () => startReceive($('offer-input').value));
  $('offer-input').addEventListener('keydown', (e) => { if (e.key === 'Enter') startReceive($('offer-input').value); });

  function defaultSaveName() { return 'pairwise-' + new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19).replace('T', '_'); }
  function cleanFileName(name) {
    const n = String(name || '').replace(/[\u0000-\u001f\u007f<>:"/\\|?*]/g, '_').replace(/^[.\s]+|[.\s]+$/g, '').slice(0, 200);
    return n || defaultSaveName();
  }
  $('btn-copy-all').addEventListener('click', () => { if (receivedText !== null) copyText(receivedText, nf.format(receivedText.length) + ' characters'); });
  $('btn-download').addEventListener('click', async () => {
    if (receivedText === null) return;
    const name = cleanFileName($('save-name').value);
    $('save-name').value = name;
    const blob = new Blob([receivedText], { type: 'application/octet-stream' });
    if (typeof window.showSaveFilePicker === 'function') {
      try {
        const handle = await window.showSaveFilePicker({ suggestedName: name });
        const w = await handle.createWritable(); await w.write(blob); await w.close();
        toast('Saved ' + handle.name); log('Saved ' + fmtBytes(blob.size) + ' to ' + handle.name); return;
      } catch (e) { if (e && e.name === 'AbortError') return; }
    }
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = name;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 60000);
    log('Downloaded ' + fmtBytes(blob.size) + ' as ' + name);
  });
  $('btn-recv-clear').addEventListener('click', () => {
    receivedText = null; recvView.clear();
    $('recv-result').hidden = true; $('recv-connect').hidden = false;
    $('offer-input').value = ''; $('offer-error').textContent = ''; $('save-name').value = '';
    log('Received text cleared from this page');
  });

  // ============================================================ startup
  function checkEnvironment() {
    const missing = [];
    if (!window.isSecureContext) missing.push('a secure (HTTPS) page');
    if (!window.crypto || !window.crypto.subtle) missing.push('the Web Crypto API');
    if (typeof TextEncoder === 'undefined' || !TextEncoder.prototype.encodeInto) missing.push('TextEncoder.encodeInto');
    if (typeof fetch === 'undefined') missing.push('the Fetch API');
    if (missing.length) {
      const w = $('env-warning'); w.hidden = false;
      w.textContent = 'This browser or page context is missing ' + missing.join(', ') + '. Pairwise cannot run here. Open it over HTTPS (or localhost) in a current Chrome, Edge, Firefox or Safari.';
      $('btn-send').disabled = true;
      return false;
    }
    return true;
  }

  const envOk = checkEnvironment();
  updateStats();
  if (envOk) {
    NET.health().then((h) => { if (h && h.maxBytes) { serverLimits = h; updateStats(); } }).catch(() => {});
  }
  if (location.hash.startsWith('#' + LT.PROTO + 'b!') || location.hash.startsWith('#' + encodeURIComponent(LT.PROTO + 'b!'))) {
    const frag = location.hash;
    try { history.replaceState(null, '', location.pathname + location.search); } catch (e) { /* ignore */ }
    showTab('recv');
    if (envOk) startReceive(frag);
  }

  if (TEST) {
    window.__pw = {
      received: () => receivedText,
      senderText: () => currentText(),
      loadText,
      isBig: () => bigText !== null,
      lastLink: null,
      activeId: () => (active ? active.id : null)
    };
  }
})();
