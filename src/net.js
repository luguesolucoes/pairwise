/* Pairwise network client: uploads the encrypted blob and downloads it back.
 * Same-origin by default (the server serves this page). No DOM. Exposed as window.NET. */
(function (global) {
  'use strict';

  function apiBase() {
    try {
      const q = new URLSearchParams(global.location.search);
      if (/[?&]test=1\b/.test(global.location.search) && q.get('api')) return q.get('api').replace(/\/$/, '');
    } catch (e) { /* ignore */ }
    try { return global.location.origin; } catch (e) { return ''; }
  }

  function errorFor(status, payload) {
    const code = payload && payload.error;
    if (status === 413 || code === 'too_large') return 'The text is larger than this server accepts.';
    if (status === 404 || code === 'not_found') return 'This transfer no longer exists. It may have expired or already been opened.';
    if (status === 0) return 'Could not reach the server. Check your connection and that the server is running.';
    return 'Server error (' + status + (code ? ', ' + code : '') + ').';
  }

  /** POST a Blob of ciphertext. Resolves { id, expiresAt, size }. Reports upload progress. */
  function uploadBlob(blob, opts) {
    opts = opts || {};
    const base = apiBase();
    const qs = '?ttl=' + encodeURIComponent(opts.ttl || 900) + (opts.once ? '&once=1' : '');
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', base + '/api/blob' + qs);
      xhr.responseType = 'json';
      xhr.setRequestHeader('Content-Type', 'application/octet-stream');
      if (xhr.upload && opts.onProgress) {
        xhr.upload.onprogress = (e) => { if (e.lengthComputable) opts.onProgress(e.loaded, e.total); };
      }
      xhr.onload = () => {
        const body = xhr.response || (() => { try { return JSON.parse(xhr.responseText); } catch (e) { return null; } })();
        if (xhr.status === 201 && body && body.id) resolve(body);
        else reject(new Error(errorFor(xhr.status, body)));
      };
      xhr.onerror = () => reject(new Error(errorFor(0)));
      xhr.onabort = () => reject(new DOMException('Cancelled', 'AbortError'));
      if (opts.signal) {
        if (opts.signal.aborted) { xhr.abort(); return; }
        opts.signal.addEventListener('abort', () => xhr.abort(), { once: true });
      }
      xhr.send(blob);
    });
  }

  async function getMeta(id) {
    const base = apiBase();
    let res;
    try { res = await fetch(base + '/api/blob/' + encodeURIComponent(id) + '/meta', { cache: 'no-store' }); }
    catch (e) { throw new Error(errorFor(0)); }
    if (res.status === 404) return null;
    if (!res.ok) throw new Error(errorFor(res.status));
    return res.json();
  }

  /** Stream the blob back, calling onChunk(Uint8Array) and onProgress(loaded, total). */
  async function downloadStream(id, opts) {
    opts = opts || {};
    const base = apiBase();
    let res;
    try { res = await fetch(base + '/api/blob/' + encodeURIComponent(id), { cache: 'no-store', signal: opts.signal }); }
    catch (e) { if (e && e.name === 'AbortError') throw e; throw new Error(errorFor(0)); }
    if (!res.ok) { let body = null; try { body = await res.json(); } catch (e) { /* ignore */ } throw new Error(errorFor(res.status, body)); }
    const total = +(res.headers.get('Content-Length') || 0) || 0;
    let loaded = 0;
    if (!res.body || !res.body.getReader) {
      const buf = new Uint8Array(await res.arrayBuffer());
      if (opts.onChunk) opts.onChunk(buf);
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

  global.NET = { apiBase, uploadBlob, getMeta, downloadStream, destroy, health };
})(typeof window !== 'undefined' ? window : globalThis);
