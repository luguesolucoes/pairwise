/* Pairwise core: encoding, chunking, crypto, framing, compact signaling.
 * Pure functions only (no DOM). Exposed as window.LT for the UI and tests.
 * Uses only the Web Crypto API; no custom cryptography. */
(function (global) {
  'use strict';

  const PROTO = 'pw1';
  const CHUNK_BYTES = 48 * 1024;          // plaintext bytes per chunk (frame stays < 64 KiB)
  const FRAME_HEADER = 5;                 // u8 type + u32 index
  const GCM_TAG = 16;
  const T_DATA = 1, T_MANIFEST = 2;
  const te = new TextEncoder();
  const subtle = global.crypto && global.crypto.subtle;

  // ---------- byte helpers ----------
  function rand(n) { return global.crypto.getRandomValues(new Uint8Array(n)); }

  function b64u(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i += 0x8000) {
      s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    }
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function unb64u(str) {
    if (typeof str !== 'string' || !/^[A-Za-z0-9_-]*$/.test(str)) throw new Error('Invalid base64url data');
    let s = str.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function hex(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
    return s;
  }

  function concat(a, b) {
    const out = new Uint8Array(a.length + b.length);
    out.set(a, 0); out.set(b, a.length);
    return out;
  }

  function equalBytes(a, b) {
    if (a.length !== b.length) return false;
    let d = 0;
    for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
    return d === 0;
  }

  // ---------- text statistics ----------
  /** UTF-8 byte length without allocating an encoded copy. Lone surrogates count as 3 (U+FFFD). */
  function utf8Length(str) {
    let n = 0;
    for (let i = 0; i < str.length; i++) {
      const c = str.charCodeAt(i);
      if (c < 0x80) n += 1;
      else if (c < 0x800) n += 2;
      else if (c >= 0xD800 && c <= 0xDBFF && i + 1 < str.length) {
        const d = str.charCodeAt(i + 1);
        if (d >= 0xDC00 && d <= 0xDFFF) { n += 4; i++; } else n += 3;
      } else n += 3;
    }
    return n;
  }

  function countLines(str) {
    if (str.length === 0) return 0;
    let n = 1, i = -1;
    while ((i = str.indexOf('\n', i + 1)) !== -1) n++;
    return n;
  }

  /** Count unpaired UTF-16 surrogates; UTF-8 cannot carry them, so they become U+FFFD. */
  function countUnpairedSurrogates(str) {
    if (typeof str.isWellFormed === 'function' && str.isWellFormed()) return 0;
    let n = 0;
    for (let i = 0; i < str.length; i++) {
      const c = str.charCodeAt(i);
      if (c >= 0xD800 && c <= 0xDBFF) {
        const d = i + 1 < str.length ? str.charCodeAt(i + 1) : 0;
        if (d >= 0xDC00 && d <= 0xDFFF) i++; else n++;
      } else if (c >= 0xDC00 && c <= 0xDFFF) n++;
    }
    return n;
  }

  /** Line start offsets (UTF-16 indices) for virtualized rendering. */
  function lineIndex(str) {
    const lines = countLines(str);
    const starts = new Uint32Array(Math.max(lines, 1));
    let k = 1, i = -1;
    while ((i = str.indexOf('\n', i + 1)) !== -1) starts[k++] = i + 1;
    return starts;
  }

  // ---------- chunking ----------
  /** Encode the chunk starting at UTF-16 index `pos` into `buf`. Never splits a code point. */
  function encodeChunkAt(str, pos, buf) {
    let end = Math.min(str.length, pos + buf.length);
    if (end < str.length) {
      const last = str.charCodeAt(end - 1);
      if (last >= 0xD800 && last <= 0xDBFF) end++; // keep surrogate pairs together in the slice
    }
    const r = te.encodeInto(str.substring(pos, end), buf);
    if (r.read === 0 && pos < str.length) throw new Error('Chunk buffer too small');
    return { read: r.read, written: r.written };
  }

  /**
   * Single pass over the text: computes chunk boundaries, sizes and the integrity digest.
   * Integrity: h0 = 32 zero bytes; h_i = SHA-256(h_{i-1} || chunk_i);
   * digest = SHA-256(h_n || u64 totalBytes || u32 count).
   */
  async function prepare(str, opts) {
    opts = opts || {};
    const chunkBytes = opts.chunkBytes || CHUNK_BYTES;
    const onProgress = opts.onProgress || function () {};
    const signal = opts.signal;
    const buf = new Uint8Array(chunkBytes);
    const starts = [];
    const sizes = [];
    let pos = 0, totalBytes = 0;
    let h = new Uint8Array(32);
    while (pos < str.length) {
      if (signal && signal.aborted) throw new DOMException('Cancelled', 'AbortError');
      const r = encodeChunkAt(str, pos, buf);
      starts.push(pos); sizes.push(r.written);
      h = new Uint8Array(await subtle.digest('SHA-256', concat(h, buf.subarray(0, r.written))));
      pos += r.read; totalBytes += r.written;
      if (starts.length % 64 === 0) onProgress(pos / str.length);
    }
    onProgress(1);
    const count = starts.length;
    const digest = await finalDigest(h, totalBytes, count);
    return {
      starts: Uint32Array.from(starts),
      sizes: Uint32Array.from(sizes),
      count, totalBytes,
      chars: str.length,
      lines: countLines(str),
      unpaired: countUnpairedSurrogates(str),
      digest, chunkBytes
    };
  }

  async function finalDigest(h, totalBytes, count) {
    const tail = new Uint8Array(12);
    const dv = new DataView(tail.buffer);
    dv.setUint32(0, Math.floor(totalBytes / 0x100000000));
    dv.setUint32(4, totalBytes >>> 0);
    dv.setUint32(8, count);
    return new Uint8Array(await subtle.digest('SHA-256', concat(h, tail)));
  }

  async function chainStep(h, chunk) {
    return new Uint8Array(await subtle.digest('SHA-256', concat(h, chunk)));
  }

  /** Re-encode chunk i into buf; verifies the size matches the prepared plan. */
  function chunkBytesAt(str, manifest, i, buf) {
    const r = encodeChunkAt(str, manifest.starts[i], buf);
    if (r.written !== manifest.sizes[i]) throw new Error('Text changed after preparing the transfer');
    return buf.subarray(0, r.written);
  }

  // ---------- keys ----------
  async function importMaster(raw) {
    if (!(raw instanceof Uint8Array) || raw.length !== 32) throw new Error('Key must be 32 bytes');
    return subtle.importKey('raw', raw, 'HKDF', false, ['deriveKey']);
  }

  async function deriveKeys(master, sid) {
    const enc = await subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: sid, info: te.encode(PROTO + '/enc') },
      master, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    const auth = await subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: sid, info: te.encode(PROTO + '/auth') },
      master, { name: 'HMAC', hash: 'SHA-256', length: 256 }, false, ['sign', 'verify']);
    return { enc, auth };
  }

  /** New session: 16-byte session id + 32-byte master key (only ever in the URL fragment). */
  async function newSession() {
    const sid = rand(16), key = rand(32);
    const keys = await deriveKeys(await importMaster(key), sid);
    return { sid, key, keys };
  }

  async function openSession(sid, key) {
    if (sid.length !== 16) throw new Error('Invalid session id');
    return { sid, key, keys: await deriveKeys(await importMaster(key), sid) };
  }

  // ---------- framing ----------
  // IV (96 bit) = u32 frame type || u64 index. The key is unique per session and each
  // (type, index) pair encrypts exactly one fixed plaintext, so nonces never repeat with
  // different plaintexts, including on resume.
  function ivFor(type, index) {
    const iv = new Uint8Array(12);
    const dv = new DataView(iv.buffer);
    dv.setUint32(0, type);
    dv.setUint32(8, index);
    return iv;
  }

  function aadFor(sid, type, index, count) {
    const a = new Uint8Array(16 + 9);
    a.set(sid, 0);
    const dv = new DataView(a.buffer);
    dv.setUint8(16, type);
    dv.setUint32(17, index);
    dv.setUint32(21, count);
    return a;
  }

  async function sealFrame(sess, type, index, count, plain) {
    const ct = new Uint8Array(await subtle.encrypt(
      { name: 'AES-GCM', iv: ivFor(type, index), additionalData: aadFor(sess.sid, type, index, count), tagLength: 128 },
      sess.keys.enc, plain));
    const frame = new Uint8Array(FRAME_HEADER + ct.length);
    const dv = new DataView(frame.buffer);
    dv.setUint8(0, type);
    dv.setUint32(1, index);
    frame.set(ct, FRAME_HEADER);
    return frame;
  }

  function frameHeader(frame) {
    if (frame.byteLength < FRAME_HEADER + GCM_TAG) throw new Error('Frame too short');
    const dv = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
    return { type: dv.getUint8(0), index: dv.getUint32(1) };
  }

  /** Throws (OperationError) if the frame was tampered with, reordered or replayed from another session. */
  async function openFrame(sess, frame, count) {
    const { type, index } = frameHeader(frame);
    const pt = await subtle.decrypt(
      { name: 'AES-GCM', iv: ivFor(type, index), additionalData: aadFor(sess.sid, type, index, count), tagLength: 128 },
      sess.keys.enc, frame.subarray(FRAME_HEADER));
    return { type, index, plain: new Uint8Array(pt) };
  }

  function encodeManifest(m, expiresAt) {
    return te.encode(JSON.stringify({
      v: 1, count: m.count, bytes: m.totalBytes, chars: m.chars, lines: m.lines,
      unpaired: m.unpaired, digest: hex(m.digest), exp: expiresAt
    }));
  }

  function decodeManifest(bytes) {
    const o = JSON.parse(new TextDecoder().decode(bytes));
    const ok = o && o.v === 1 && Number.isSafeInteger(o.count) && o.count >= 0 &&
      Number.isSafeInteger(o.bytes) && o.bytes >= 0 && /^[0-9a-f]{64}$/.test(o.digest);
    if (!ok) throw new Error('Malformed manifest');
    return o;
  }

  async function authTag(sess, nonce) {
    return new Uint8Array(await subtle.sign('HMAC', sess.keys.auth, concat(te.encode(PROTO + '/resp'), concat(sess.sid, nonce))));
  }

  async function authVerify(sess, nonce, tag) {
    return subtle.verify('HMAC', sess.keys.auth, tag, concat(te.encode(PROTO + '/resp'), concat(sess.sid, nonce)));
  }

  // ---------- compact signaling (SDP <-> short string for QR codes) ----------
  // Only what a data-channel-only session needs: ICE credentials, DTLS fingerprint,
  // DTLS role, max message size and UDP candidates. Everything else is a fixed template.
  const CAND_TYPES = { host: 'h', srflx: 's', relay: 'r', prflx: 'p' };
  const CAND_NAMES = { h: 'host', s: 'srflx', r: 'relay', p: 'prflx' };
  const SETUP = { actpass: 'x', active: 'a', passive: 'p' };
  const SETUP_NAMES = { x: 'actpass', a: 'active', p: 'passive' };

  function compactSdp(sdp) {
    const get = (re) => { const m = sdp.match(re); return m ? m[1].trim() : null; };
    const ufrag = get(/^a=ice-ufrag:(.+)$/m);
    const pwd = get(/^a=ice-pwd:(.+)$/m);
    const fp = get(/^a=fingerprint:sha-256 (.+)$/mi);
    const setup = get(/^a=setup:(\w+)$/m) || 'actpass';
    const mms = get(/^a=max-message-size:(\d+)$/m) || '65536';
    if (!ufrag || !pwd || !fp) throw new Error('Session description is missing ICE or DTLS data');
    const fpBytes = new Uint8Array(fp.split(':').map((x) => parseInt(x, 16)));
    if (fpBytes.length !== 32 || fpBytes.some((x) => Number.isNaN(x))) throw new Error('Unsupported DTLS fingerprint');
    const cands = [];
    const seen = new Set();
    const re = /^a=candidate:\S+ (\d+) (\S+) \d+ (\S+) (\d+) typ (\w+)/gm;
    let m;
    while ((m = re.exec(sdp))) {
      const [, comp, proto, addr, port, typ] = m;
      if (comp !== '1' || proto.toLowerCase() !== 'udp' || !CAND_TYPES[typ]) continue;
      const k = addr + ':' + port;
      if (seen.has(k)) continue;
      seen.add(k);
      cands.push(CAND_TYPES[typ] + ',' + addr + ',' + port);
    }
    if (!cands.length) throw new Error('No usable network candidates were found');
    for (const s of [ufrag, pwd]) if (/[~!,\s]/.test(s)) throw new Error('Unexpected ICE credential format');
    return [ufrag, pwd, b64u(fpBytes), SETUP[setup] || 'x', mms].concat(cands).join('~');
  }

  function expandSdp(compact) {
    const parts = String(compact).split('~');
    if (parts.length < 6) throw new Error('Pairing data is incomplete');
    const [ufrag, pwd, fpB64, setupC, mms] = parts;
    const fpBytes = unb64u(fpB64);
    if (fpBytes.length !== 32) throw new Error('Pairing data has an invalid fingerprint');
    if (!SETUP_NAMES[setupC] || !/^\d{1,9}$/.test(mms)) throw new Error('Pairing data is malformed');
    const fpHex = Array.from(fpBytes, (b) => b.toString(16).padStart(2, '0').toUpperCase()).join(':');
    const sessId = String(Date.now()) + String(Math.floor(Math.random() * 1e6));
    const L = [
      'v=0', 'o=- ' + sessId + ' 2 IN IP4 127.0.0.1', 's=-', 't=0 0',
      'a=group:BUNDLE 0', 'a=msid-semantic: WMS',
      'm=application 9 UDP/DTLS/SCTP webrtc-datachannel', 'c=IN IP4 0.0.0.0',
      'a=ice-ufrag:' + ufrag, 'a=ice-pwd:' + pwd, 'a=ice-options:trickle',
      'a=fingerprint:sha-256 ' + fpHex, 'a=setup:' + SETUP_NAMES[setupC],
      'a=mid:0', 'a=sctp-port:5000', 'a=max-message-size:' + mms
    ];
    const base = { h: 2130706431, p: 1862270975, s: 1694498815, r: 16777215 };
    parts.slice(5).forEach((c, i) => {
      const [t, addr, port] = c.split(',');
      if (!CAND_NAMES[t] || !addr || !/^\d{1,5}$/.test(port) || /\s/.test(addr)) throw new Error('Pairing data has an invalid candidate');
      let line = 'a=candidate:' + (i + 1) + ' 1 udp ' + (base[t] - i) + ' ' + addr + ' ' + port + ' typ ' + CAND_NAMES[t];
      if (t !== 'h') line += ' raddr 0.0.0.0 rport 0';
      L.push(line);
    });
    L.push('a=end-of-candidates');
    return L.join('\r\n') + '\r\n';
  }

  // Offer link fragment: #pw1!<sid>!<key>!<compact offer>   (key never leaves the fragment)
  // Answer code:          pwa1!<sid>!<compact answer>        (contains no key material)
  function offerFragment(sess, compact) {
    return PROTO + '!' + b64u(sess.sid) + '!' + b64u(sess.key) + '!' + compact;
  }

  function parseOffer(text) {
    let s = String(text || '').trim();
    const h = s.indexOf('#');
    if (h !== -1) s = s.slice(h + 1);
    try { s = decodeURIComponent(s); } catch (e) { /* keep raw */ }
    const parts = s.split('!');
    if (parts.length !== 4 || parts[0] !== PROTO) throw new Error('This is not a Pairwise sender code');
    const sid = unb64u(parts[1]), key = unb64u(parts[2]);
    if (sid.length !== 16 || key.length !== 32) throw new Error('Sender code is damaged');
    expandSdp(parts[3]); // validate
    return { sid, key, compact: parts[3] };
  }

  function answerCode(sid, compact) { return 'pwa1!' + b64u(sid) + '!' + compact; }

  function parseAnswer(text) {
    let s = String(text || '').trim();
    try { s = decodeURIComponent(s); } catch (e) { /* keep raw */ }
    const parts = s.split('!');
    if (parts.length !== 3 || parts[0] !== 'pwa1') throw new Error('This is not a Pairwise answer code');
    const sid = unb64u(parts[1]);
    if (sid.length !== 16) throw new Error('Answer code is damaged');
    expandSdp(parts[2]);
    return { sid, compact: parts[2] };
  }

  global.LT = {
    PROTO, CHUNK_BYTES, FRAME_HEADER, GCM_TAG, T_DATA, T_MANIFEST,
    rand, b64u, unb64u, hex, concat, equalBytes,
    utf8Length, countLines, countUnpairedSurrogates, lineIndex,
    encodeChunkAt, prepare, finalDigest, chainStep, chunkBytesAt,
    newSession, openSession, sealFrame, openFrame, frameHeader,
    encodeManifest, decodeManifest, authTag, authVerify,
    compactSdp, expandSdp, offerFragment, parseOffer, answerCode, parseAnswer
  };
})(typeof window !== 'undefined' ? window : globalThis);
