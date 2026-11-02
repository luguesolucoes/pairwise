/* Pairwise core: encoding, chunking, crypto, framing and the stored-blob format.
 * Pure functions only (no DOM, no network). Exposed as window.LT for the UI and tests.
 * Uses only the Web Crypto API; no custom cryptography. */
(function (global) {
  'use strict';

  const PROTO = 'pw1';
  const CHUNK_BYTES = 48 * 1024;          // plaintext bytes per chunk
  const FRAME_HEADER = 5;                 // u8 type + u32 index
  const GCM_TAG = 16;
  const T_DATA = 1, T_MANIFEST = 2;
  const MAGIC = new Uint8Array([0x50, 0x57, 0x42, 0x31]); // "PWB1"
  const MAX_FRAME = CHUNK_BYTES + FRAME_HEADER + GCM_TAG + 64;
  const te = new TextEncoder();
  const subtle = global.crypto && global.crypto.subtle;

  // ---------- byte helpers ----------
  function rand(n) { return global.crypto.getRandomValues(new Uint8Array(n)); }

  function b64u(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
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

  function u32be(n) { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0); return b; }

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
  // The 32-byte master key lives only in the URL fragment. HKDF-SHA-256, salted with the
  // 16-byte session id, derives one non-extractable AES-256-GCM key. The server never sees
  // the master key or the derived key.
  async function importMaster(raw) {
    if (!(raw instanceof Uint8Array) || raw.length !== 32) throw new Error('Key must be 32 bytes');
    return subtle.importKey('raw', raw, 'HKDF', false, ['deriveKey']);
  }

  async function deriveKeys(master, sid) {
    const enc = await subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: sid, info: te.encode(PROTO + '/enc') },
      master, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    return { enc };
  }

  async function newSession() {
    const sid = rand(16), key = rand(32);
    return { sid, key, keys: await deriveKeys(await importMaster(key), sid) };
  }

  async function openSession(sid, key) {
    if (sid.length !== 16 || key.length !== 32) throw new Error('Invalid session material');
    return { sid, key, keys: await deriveKeys(await importMaster(key), sid) };
  }

  // ---------- framing ----------
  // IV (96 bit) = u32 frame type || u64 index. The key is unique per blob and each
  // (type, index) pair encrypts exactly one fixed plaintext, so nonces never repeat.
  function ivFor(type, index) {
    const iv = new Uint8Array(12);
    const dv = new DataView(iv.buffer);
    dv.setUint32(0, type);
    dv.setUint32(8, index);
    return iv;
  }

  // AAD = session id || frame type || index || total count. Binds every chunk to its
  // position and to this session, so altered, reordered, truncated or foreign chunks fail.
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

  /** Throws (OperationError) if the frame was tampered with, reordered or sealed with a different key. */
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
      unpaired: m.unpaired, digest: hex(m.digest), exp: expiresAt || 0
    }));
  }

  function decodeManifest(bytes) {
    const o = JSON.parse(new TextDecoder().decode(bytes));
    const ok = o && o.v === 1 && Number.isSafeInteger(o.count) && o.count >= 0 &&
      Number.isSafeInteger(o.bytes) && o.bytes >= 0 && /^[0-9a-f]{64}$/.test(o.digest);
    if (!ok) throw new Error('Malformed manifest');
    return o;
  }

  // ---------- stored blob format ----------
  // MAGIC "PWB1" then length-prefixed records: [u32 len][frame]. Record 0 is the manifest
  // frame; records 1..count are the data frames in order. This is what gets uploaded.
  function blobRecord(frame) { return [u32be(frame.length), frame]; }

  /** Incrementally splits a downloaded blob stream back into whole frames. */
  class FrameSplitter {
    constructor(maxFrame) {
      this.max = maxFrame || MAX_FRAME;
      this.buf = new Uint8Array(0);
      this.off = 0;
      this.magicChecked = false;
    }
    _pending() { return this.buf.length - this.off; }
    push(chunk) {
      if (chunk && chunk.length) {
        const merged = new Uint8Array(this._pending() + chunk.length);
        merged.set(this.buf.subarray(this.off), 0);
        merged.set(chunk, this._pending());
        this.buf = merged; this.off = 0;
      }
      const frames = [];
      if (!this.magicChecked) {
        if (this._pending() < MAGIC.length) return frames;
        if (!equalBytes(this.buf.subarray(this.off, this.off + MAGIC.length), MAGIC)) throw new Error('Not a Pairwise blob');
        this.off += MAGIC.length;
        this.magicChecked = true;
      }
      for (;;) {
        if (this._pending() < 4) break;
        const len = new DataView(this.buf.buffer, this.buf.byteOffset + this.off, 4).getUint32(0);
        if (len < FRAME_HEADER + GCM_TAG || len > this.max) throw new Error('Corrupt blob framing');
        if (this._pending() < 4 + len) break;
        frames.push(this.buf.slice(this.off + 4, this.off + 4 + len));
        this.off += 4 + len;
      }
      if (this.off > 0) { this.buf = this.buf.slice(this.off); this.off = 0; }
      return frames;
    }
    end() { if (this._pending() !== 0 || !this.magicChecked) throw new Error('Blob ended mid-frame (truncated download)'); }
  }

  // ---------- retrieval link ----------
  // Fragment: #pw1b!<sid b64url>!<key b64url>!<blob id>. The key is in the fragment, so it
  // never reaches the server; the server only ever learns the blob id.
  function retrieveFragment(sess, id) {
    return PROTO + 'b!' + b64u(sess.sid) + '!' + b64u(sess.key) + '!' + id;
  }

  function parseRetrieve(text) {
    let s = String(text || '').trim();
    const h = s.indexOf('#');
    if (h !== -1) s = s.slice(h + 1);
    try { s = decodeURIComponent(s); } catch (e) { /* keep raw */ }
    const parts = s.split('!');
    if (parts.length !== 4 || parts[0] !== PROTO + 'b') throw new Error('This is not a Pairwise retrieval link');
    const sid = unb64u(parts[1]), key = unb64u(parts[2]), id = parts[3];
    if (sid.length !== 16 || key.length !== 32) throw new Error('Retrieval link is damaged');
    if (!/^[0-9a-f]{24,64}$/.test(id)) throw new Error('Retrieval link has an invalid id');
    return { sid, key, id };
  }

  global.LT = {
    PROTO, CHUNK_BYTES, FRAME_HEADER, GCM_TAG, T_DATA, T_MANIFEST, MAGIC, MAX_FRAME,
    rand, b64u, unb64u, hex, concat, equalBytes, u32be,
    utf8Length, countLines, countUnpairedSurrogates, lineIndex,
    encodeChunkAt, prepare, finalDigest, chainStep, chunkBytesAt,
    newSession, openSession, sealFrame, openFrame, frameHeader,
    encodeManifest, decodeManifest,
    blobRecord, FrameSplitter, retrieveFragment, parseRetrieve
  };
})(typeof window !== 'undefined' ? window : globalThis);
