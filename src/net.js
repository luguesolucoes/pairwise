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
  // Free hosts (Render and the like) spin down when idle and can take up to ~60 s to wake.
  // Wait out a full cold start before giving up, reporting elapsed seconds so it never looks stuck.
  const WAKE_MS = 150000;
  const RETRY_MS = 150000;

  function errorFor(status, payload) {
    const code = payload && payload.error;
    if (status === 413 || code === 'too_large') return 'The text is larger than this server accepts.';
    if (status === 404 || code === 'not_found') return 'This transfer no longer exists. It may have expired or already been opened.';
    if (status === 0) return 'Could not reach the server. Check your connection and that the server is running.';
    if (TRANSIENT.has(status)) return 'The server is waking up and did not respond in time. Wait a few seconds and try again.';
    return 'Server error (' + status + (code ? ', ' + code : '') + ').';
  }

  /** Ping /api/health until the instance answers, riding out a cold start (up to WAKE_MS).
   *  Reports elapsed seconds through onWait. Resolves true when ready, false on timeout. */
  async function wake(opts) {
    opts = opts || {};
    const deadline = Date.now() + (opts.budgetMs || WAKE_MS);
    let first = true;
    while (Date.now() < deadline) {
      if (opts.signal && opts.signal.aborted) throw new DOMException('Cancelled', 'AbortError');
      try {
        // No per-request timeout: a free host often holds the first request open until it is up.
        const r = await fetch(apiBase() + '/api/health', { cache: 'no-store', signal: opts.signal });
        if (r.ok) return true;
      } catch (e) { if (e && e.name === 'AbortError') throw e; }
      if (opts.onWait) opts.onWait(Math.round((Date.now() - (deadline - (opts.budgetMs || WAKE_MS))) / 1000));
      if (!first) await sleep(3000);
      first = false;
    }
    return false;
  }

  function postOnce(url, blob, onProgress, signal) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', url);
      xhr.setRequestHeader('Content-Type', 'application/octet-stream');
      if (xhr.upload && onProgress) xhr.upload.onprogress = (e) => { if (e.lengthComputable) onProgress(e.loaded, e.total); };
      xhr.onload = () => {
        let body = null; try { body = JSON.parse(xhr.responseText); } catch (e) { /* not JSON */ }
        // Who answered, for diagnosis: our server, Render's edge, or a proxy in between.
        let via = '';
        try { via = (xhr.getResponseHeader('server') || '') + (xhr.getResponseHeader('cf-ray') ? ' cf' : '') + (xhr.getResponseHeader('x-render-routing') ? ' render:' + xhr.getResponseHeader('x-render-routing') : ''); } catch (e) { /* ignore */ }
        const snippet = body ? '' : (xhr.responseText || '').replace(/\s+/g, ' ').trim().slice(0, 100);
        resolve({ status: xhr.status, body, via: via.trim(), snippet });
      };
      xhr.onerror = () => resolve({ status: 0, body: null, via: 'network error', snippet: '' });
      xhr.ontimeout = () => resolve({ status: 0, body: null, via: 'timeout', snippet: '' });
      xhr.onabort = () => reject(new DOMException('Cancelled', 'AbortError'));
      if (signal) {
        if (signal.aborted) { xhr.abort(); return; }
        signal.addEventListener('abort', () => xhr.abort(), { once: true });
      }
      xhr.send(blob);
    });
  }

  function attemptLabel(r) { return 'HTTP ' + r.status + (r.via ? ' (' + r.via + ')' : '') + (r.snippet ? ' — ' + r.snippet : ''); }

  /** Store a Blob of ciphertext. Resolves { id, expiresAt, size }. Retries cold-start rejections. */
  async function uploadBlob(blob, opts) {
    opts = opts || {};
    const base = apiBase();
    const qs = '?ttl=' + encodeURIComponent(opts.ttl || 900) + (opts.once ? '&once=1' : '');
    const url = base + '/api/blob' + qs;
    const start = Date.now();
    let last = { status: 0, body: null };
    do {
      last = await postOnce(url, blob, opts.onProgress, opts.signal);
      if (opts.onAttempt) opts.onAttempt(attemptLabel(last));
      if (last.status === 201 && last.body && last.body.id) return last.body;
      if (last.status === 201 && (!last.body || !last.body.id)) throw new Error('The server accepted the data but the reply was altered on the way back (' + attemptLabel(last) + '). A proxy may be rewriting responses.');
      if (!TRANSIENT.has(last.status)) break;
      if (opts.onWait) opts.onWait(Math.round((Date.now() - start) / 1000));
      await sleep(3000);
    } while (Date.now() - start < RETRY_MS);
    throw new Error('Pairing kept failing: ' + attemptLabel(last) + '. ' + errorFor(last.status, last.body));
  }

  async function getMeta(id, opts) {
    opts = opts || {};
    const base = apiBase();
    const start = Date.now();
    for (;;) {
      let res;
      try { res = await fetch(base + '/api/blob/' + encodeURIComponent(id) + '/meta', { cache: 'no-store', signal: opts.signal }); }
      catch (e) { if (e && e.name === 'AbortError') throw e; res = null; }
      if (res && res.status === 404) return null;
      if (res && res.ok) return res.json();
      if (res && !TRANSIENT.has(res.status)) throw new Error(errorFor(res.status));
      if (Date.now() - start >= RETRY_MS) throw new Error(errorFor(res ? res.status : 0));
      if (opts.onWait) opts.onWait(Math.round((Date.now() - start) / 1000));
      await sleep(3000);
    }
  }

  /** Stream the blob back, calling onChunk(Uint8Array) and onProgress(loaded, total).
   *  The opening request is retried on a cold start; once bytes flow it is not. */
  async function downloadStream(id, opts) {
    opts = opts || {};
    const base = apiBase();
    const url = base + '/api/blob/' + encodeURIComponent(id);
    const start = Date.now();
    let res = null;
    for (;;) {
      try { res = await fetch(url, { cache: 'no-store', signal: opts.signal }); }
      catch (e) { if (e && e.name === 'AbortError') throw e; res = null; }
      if (res && res.ok) break;
      if (res && !TRANSIENT.has(res.status)) { let body = null; try { body = await res.json(); } catch (e) { /* ignore */ } throw new Error(errorFor(res.status, body)); }
      if (Date.now() - start >= RETRY_MS) throw new Error(errorFor(res ? res.status : 0));
      if (opts.onWait) opts.onWait(Math.round((Date.now() - start) / 1000));
      await sleep(3000);
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
