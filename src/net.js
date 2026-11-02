/* Pairwise network client: pairs (stores) the encrypted blob and retrieves it.
 * Same-origin by default (the server serves this page). No DOM. Exposed as window.NET.
 * Absorbs free-tier cold starts: transient 403/429/5xx are retried with backoff. */
(function (global) {
  'use strict';

  function apiBase() {
    try {
      const q = new URLSearchParams(global.location.search);
      if (/[?&]test=1\b/.test(global.location.search) && q.get('api')) return q.get('api').replace(/\/$/, '');
    } catch (e) { /* ignore */ }
    try { return global.location.origin; } catch (e) { return ''; }
  }

  // Statuses a sleeping/waking instance (or its edge) returns before it is ready.
  const TRANSIENT = new Set([403, 408, 425, 429, 500, 502, 503, 504]);
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  function errorFor(status, payload) {
    const code = payload && payload.error;
    if (status === 413 || code === 'too_large') return 'The text is larger than this server accepts.';
    if (status === 404 || code === 'not_found') return 'This transfer no longer exists. It may have expired or already been opened.';
    if (status === 0) return 'Could not reach the server. Check your connection and that the server is running.';
    if (TRANSIENT.has(status)) return 'The server is waking up and did not respond in time. Wait a few seconds and try again.';
    return 'Server error (' + status + (code ? ', ' + code : '') + ').';
  }

  /** Ping /api/health until the instance answers, so the first real request is not rejected
   *  by a cold start. Resolves true when ready, false after the attempts are exhausted. */
  async function wake(opts) {
    opts = opts || {};
    const tries = opts.tries || 12;
    for (let i = 0; i < tries; i++) {
      if (opts.signal && opts.signal.aborted) throw new DOMException('Cancelled', 'AbortError');
      try {
        const r = await fetch(apiBase() + '/api/health', { cache: 'no-store', signal: opts.signal });
        if (r.ok) return true;
      } catch (e) { if (e && e.name === 'AbortError') throw e; }
      if (opts.onWait) opts.onWait(i + 1, tries);
      await sleep(2500);
    }
    return false;
  }

  function postOnce(url, blob, onProgress, signal) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', url);
      xhr.responseType = 'json';
      xhr.setRequestHeader('Content-Type', 'application/octet-stream');
      if (xhr.upload && onProgress) xhr.upload.onprogress = (e) => { if (e.lengthComputable) onProgress(e.loaded, e.total); };
      xhr.onload = () => {
        const body = xhr.response || (() => { try { return JSON.parse(xhr.responseText); } catch (e) { return null; } })();
        resolve({ status: xhr.status, body });
      };
      xhr.onerror = () => resolve({ status: 0, body: null });
      xhr.onabort = () => reject(new DOMException('Cancelled', 'AbortError'));
      if (signal) {
        if (signal.aborted) { xhr.abort(); return; }
        signal.addEventListener('abort', () => xhr.abort(), { once: true });
      }
      xhr.send(blob);
    });
  }

  /** Store a Blob of ciphertext. Resolves { id, expiresAt, size }. Retries cold-start rejections. */
  async function uploadBlob(blob, opts) {
    opts = opts || {};
    const base = apiBase();
    const qs = '?ttl=' + encodeURIComponent(opts.ttl || 900) + (opts.once ? '&once=1' : '');
    const url = base + '/api/blob' + qs;
    const maxTries = 5;
    let last = { status: 0, body: null };
    for (let i = 0; i < maxTries; i++) {
      last = await postOnce(url, blob, opts.onProgress, opts.signal);
      if (last.status === 201 && last.body && last.body.id) return last.body;
      if (!TRANSIENT.has(last.status) || i === maxTries - 1) break;
      if (opts.onWait) opts.onWait(i + 1, maxTries);
      await sleep(2500);
    }
    throw new Error(errorFor(last.status, last.body));
  }

  async function getMeta(id, opts) {
    opts = opts || {};
    const base = apiBase();
    const maxTries = opts.tries || 6;
    for (let i = 0; i < maxTries; i++) {
      let res;
      try { res = await fetch(base + '/api/blob/' + encodeURIComponent(id) + '/meta', { cache: 'no-store', signal: opts.signal }); }
      catch (e) { if (e && e.name === 'AbortError') throw e; res = null; }
      if (res && res.status === 404) return null;
      if (res && res.ok) return res.json();
      if (res && !TRANSIENT.has(res.status)) throw new Error(errorFor(res.status));
      if (i === maxTries - 1) throw new Error(errorFor(res ? res.status : 0));
      if (opts.onWait) opts.onWait(i + 1, maxTries);
      await sleep(2500);
    }
    return null;
  }

  /** Stream the blob back, calling onChunk(Uint8Array) and onProgress(loaded, total).
   *  The opening request is retried on a cold start; once bytes flow it is not. */
  async function downloadStream(id, opts) {
    opts = opts || {};
    const base = apiBase();
    const url = base + '/api/blob/' + encodeURIComponent(id);
    const maxTries = 5;
    let res = null;
    for (let i = 0; i < maxTries; i++) {
      try { res = await fetch(url, { cache: 'no-store', signal: opts.signal }); }
      catch (e) { if (e && e.name === 'AbortError') throw e; res = null; }
      if (res && res.ok) break;
      if (res && !TRANSIENT.has(res.status)) { let body = null; try { body = await res.json(); } catch (e) { /* ignore */ } throw new Error(errorFor(res.status, body)); }
      if (i === maxTries - 1) throw new Error(errorFor(res ? res.status : 0));
      if (opts.onWait) opts.onWait(i + 1, maxTries);
      await sleep(2500);
    }
    const total = +(res.headers.get('Content-Length') || 0) || 0;
    let loaded = 0;
    if (!res.body || !res.body.getReader) {
      const buf = new Uint8Array(await res.arrayBuffer());
      if (opts.onChunk) await opts.onChunk(buf);
      if (opts.onProgress) opts.onProgress(buf.length, total || buf.length);
      return;
    }
    const reader = res.body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      loaded += value.length;
      if (opts.onChunk) await opts.onChunk(value);
      if (opts.onProgress) opts.onProgress(loaded, total);
    }
  }

  async function destroy(id) {
    const base = apiBase();
    try { await fetch(base + '/api/blob/' + encodeURIComponent(id), { method: 'DELETE', cache: 'no-store', keepalive: true }); }
    catch (e) { /* best effort */ }
  }

  async function health() {
    const base = apiBase();
    try { const r = await fetch(base + '/api/health', { cache: 'no-store' }); return r.ok ? r.json() : null; }
    catch (e) { return null; }
  }

  global.NET = { apiBase, wake, uploadBlob, getMeta, downloadStream, destroy, health };
})(typeof window !== 'undefined' ? window : globalThis);
