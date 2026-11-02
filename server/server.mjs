/* Pairwise relay server: a zero-knowledge store-and-forward for encrypted blobs.
 *
 * The browser encrypts text with AES-256-GCM before uploading, and the decryption key
 * travels only in the URL fragment of the QR code, which is never sent in any HTTP
 * request. So this server only ever handles opaque ciphertext and a random id. It never
 * sees the key or the plaintext.
 *
 * Pure Node, no dependencies. Streams uploads and downloads to and from disk so a 50 MB
 * blob never sits in server memory. Blobs expire on a time-to-live and can be set to
 * delete on first download.
 *
 * Config (environment variables):
 *   PAIRWISE_PORT        listen port (default 8787)
 *   PAIRWISE_HOST        bind address (default 0.0.0.0)
 *   PAIRWISE_STORE       directory for stored blobs (default ./data)
 *   PAIRWISE_STATIC      path to index.html to serve (default ../dist/index.html)
 *   PAIRWISE_MAX_BYTES   max upload size in bytes (default 67108864 = 64 MiB)
 *   PAIRWISE_MAX_TTL     max time-to-live in seconds (default 86400 = 24 h)
 *   PAIRWISE_TLS_CERT    PEM cert path; with PAIRWISE_TLS_KEY, serve HTTPS directly
 *   PAIRWISE_TLS_KEY     PEM key path
 *   PAIRWISE_CORS_ORIGIN if set, allow this exact Origin to call the API cross-site
 *   PAIRWISE_TRUST_PROXY "1" to read the client IP from X-Forwarded-For (behind a proxy)
 */
import http from 'node:http';
import https from 'node:https';
import crypto from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const num = (v, d) => (v && Number.isFinite(+v) ? +v : d);
const CFG = {
  // PORT is set by most app hosts (Render, Koyeb, Heroku, Railway); PAIRWISE_PORT overrides it locally.
  port: num(process.env.PAIRWISE_PORT || process.env.PORT, 8787),
  host: process.env.PAIRWISE_HOST || '0.0.0.0',
  store: path.resolve(process.env.PAIRWISE_STORE || path.join(HERE, '..', 'data')),
  staticFile: path.resolve(process.env.PAIRWISE_STATIC || path.join(HERE, '..', 'dist', 'index.html')),
  maxBytes: num(process.env.PAIRWISE_MAX_BYTES, 64 * 1024 * 1024),
  maxTtl: num(process.env.PAIRWISE_MAX_TTL, 24 * 60 * 60),
  minTtl: 60,
  corsOrigin: process.env.PAIRWISE_CORS_ORIGIN || '',
  trustProxy: process.env.PAIRWISE_TRUST_PROXY === '1',
  tlsCert: process.env.PAIRWISE_TLS_CERT || '',
  tlsKey: process.env.PAIRWISE_TLS_KEY || ''
};

fs.mkdirSync(CFG.store, { recursive: true });

const ID_RE = /^[0-9a-f]{32}$/;
const binPath = (id) => path.join(CFG.store, id + '.bin');
const metaPath = (id) => path.join(CFG.store, id + '.json');

function clientIp(req) {
  if (CFG.trustProxy) {
    const xff = req.headers['x-forwarded-for'];
    if (xff) return String(xff).split(',')[0].trim();
  }
  return req.socket.remoteAddress || '-';
}

function log(req, status, extra) {
  process.stdout.write(new Date().toISOString() + ' ' + clientIp(req) + ' ' + req.method + ' ' +
    (req.url.split('?')[0]) + ' -> ' + status + (extra ? ' ' + extra : '') + '\n');
}

function securityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
}

function applyCors(req, res) {
  if (!CFG.corsOrigin) return true;
  const origin = req.headers.origin;
  if (origin && origin === CFG.corsOrigin) {
    res.setHeader('Access-Control-Allow-Origin', CFG.corsOrigin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,DELETE,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Max-Age', '600');
  }
  return true;
}

function sendJson(req, res, status, obj) {
  const body = Buffer.from(JSON.stringify(obj));
  securityHeaders(res);
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Content-Length', body.length);
  res.setHeader('Cache-Control', 'no-store');
  res.writeHead(status);
  res.end(req.method === 'HEAD' ? undefined : body);
  log(req, status);
}

async function readMeta(id) {
  try {
    const m = JSON.parse(await fsp.readFile(metaPath(id), 'utf8'));
    if (m && Number.isFinite(m.expiresAt) && m.expiresAt > Date.now()) return m;
  } catch (e) { /* missing or unreadable */ }
  return null;
}

async function destroy(id) {
  await Promise.allSettled([fsp.unlink(binPath(id)), fsp.unlink(metaPath(id))]);
}

// ---------------------------------------------------------------- upload
function handleUpload(req, res, query) {
  const ttl = Math.min(CFG.maxTtl, Math.max(CFG.minTtl, num(query.get('ttl'), CFG.maxTtl)));
  const once = query.get('once') === '1';
  const declared = num(req.headers['content-length'], -1);
  if (declared > CFG.maxBytes) { sendJson(req, res, 413, { error: 'too_large', maxBytes: CFG.maxBytes }); req.destroy(); return; }

  const id = crypto.randomBytes(16).toString('hex');
  const part = binPath(id) + '.part';
  const out = fs.createWriteStream(part);
  let received = 0, done = false;

  const fail = (status, error) => {
    if (done) return; done = true;
    out.destroy();
    fsp.unlink(part).catch(() => {});
    if (!res.headersSent) sendJson(req, res, status, { error });
    req.destroy();
  };

  req.on('data', (chunk) => {
    received += chunk.length;
    if (received > CFG.maxBytes) { fail(413, 'too_large'); return; }
    if (!out.write(chunk)) req.pause();
  });
  out.on('drain', () => req.resume());
  req.on('aborted', () => fail(400, 'aborted'));
  req.on('error', () => fail(400, 'request_error'));
  out.on('error', () => fail(500, 'write_error'));

  req.on('end', () => {
    if (done) return; done = true;
    out.end(async () => {
      try {
        if (received < 4) { await fsp.unlink(part).catch(() => {}); return sendJson(req, res, 400, { error: 'empty' }); }
        await fsp.rename(part, binPath(id));
        const meta = { id, size: received, createdAt: Date.now(), expiresAt: Date.now() + ttl * 1000, once };
        await fsp.writeFile(metaPath(id), JSON.stringify(meta));
        sendJson(req, res, 201, { id, size: received, expiresAt: meta.expiresAt, once });
      } catch (e) {
        await destroy(id).catch(() => {});
        if (!res.headersSent) sendJson(req, res, 500, { error: 'store_failed' });
      }
    });
  });
}

// ------------------------------------------------------------- download
async function handleDownload(req, res, id) {
  if (!ID_RE.test(id)) return sendJson(req, res, 400, { error: 'bad_id' });
  const meta = await readMeta(id);
  if (!meta) return sendJson(req, res, 404, { error: 'not_found' });
  let stat;
  try { stat = await fsp.stat(binPath(id)); } catch (e) { return sendJson(req, res, 404, { error: 'not_found' }); }

  securityHeaders(res);
  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Content-Length', stat.size);
  res.setHeader('Cache-Control', 'no-store');
  res.writeHead(200);
  if (req.method === 'HEAD') { res.end(); log(req, 200, 'head'); return; }

  const stream = fs.createReadStream(binPath(id));
  stream.pipe(res);
  stream.on('error', () => { if (!res.writableEnded) res.destroy(); });
  res.on('close', () => {
    const complete = res.writableEnded;
    log(req, 200, complete ? 'sent ' + stat.size : 'client_disconnected');
    if (complete && meta.once) destroy(id).catch(() => {});
  });
}

// --------------------------------------------------------------- static
async function serveIndex(req, res) {
  try {
    const html = await fsp.readFile(CFG.staticFile);
    securityHeaders(res);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Content-Length', html.length);
    res.setHeader('Cache-Control', 'no-cache');
    res.writeHead(200);
    res.end(req.method === 'HEAD' ? undefined : html);
    log(req, 200);
  } catch (e) {
    sendJson(req, res, 500, { error: 'static_missing', detail: 'Build the page first (node build.mjs) or set PAIRWISE_STATIC.' });
  }
}

// --------------------------------------------------------------- router
const server = (CFG.tlsCert && CFG.tlsKey)
  ? https.createServer({ cert: fs.readFileSync(CFG.tlsCert), key: fs.readFileSync(CFG.tlsKey) }, route)
  : http.createServer(route);

function route(req, res) {
  let url;
  try { url = new URL(req.url, 'http://localhost'); } catch (e) { return sendJson(req, res, 400, { error: 'bad_url' }); }
  const p = url.pathname;
  applyCors(req, res);

  if (req.method === 'OPTIONS') { securityHeaders(res); res.writeHead(CFG.corsOrigin ? 204 : 405); res.end(); return; }

  if (p === '/api/health') return sendJson(req, res, 200, { ok: true, maxBytes: CFG.maxBytes, maxTtl: CFG.maxTtl });
  if (p === '/api/blob' && req.method === 'POST') return handleUpload(req, res, url.searchParams);

  const m = p.match(/^\/api\/blob\/([^/]+)(\/meta)?$/);
  if (m) {
    const id = m[1], isMeta = !!m[2];
    if (isMeta && req.method === 'GET') {
      return readMeta(id).then((meta) => meta
        ? sendJson(req, res, 200, { id, size: meta.size, expiresAt: meta.expiresAt, once: meta.once })
        : sendJson(req, res, 404, { error: 'not_found' }));
    }
    if (!isMeta && (req.method === 'GET' || req.method === 'HEAD')) return handleDownload(req, res, id);
    if (!isMeta && req.method === 'DELETE') {
      if (!ID_RE.test(id)) return sendJson(req, res, 400, { error: 'bad_id' });
      return destroy(id).then(() => { securityHeaders(res); res.writeHead(204); res.end(); log(req, 204); });
    }
    return sendJson(req, res, 405, { error: 'method_not_allowed' });
  }

  if ((req.method === 'GET' || req.method === 'HEAD') && (p === '/' || p === '/index.html')) return serveIndex(req, res);
  return sendJson(req, res, 404, { error: 'not_found' });
}

// -------------------------------------------------------- expiry sweeper
async function sweep() {
  let removed = 0;
  try {
    const files = await fsp.readdir(CFG.store);
    for (const f of files) {
      if (!f.endsWith('.json')) continue;
      const id = f.slice(0, -5);
      if (!ID_RE.test(id)) continue;
      const meta = await readMeta(id);
      if (!meta) { await destroy(id); removed++; }
    }
    // Drop stale temp files older than 10 minutes.
    for (const f of files) {
      if (!f.endsWith('.part')) continue;
      const fp = path.join(CFG.store, f);
      try { const st = await fsp.stat(fp); if (Date.now() - st.mtimeMs > 600000) await fsp.unlink(fp); } catch (e) { /* ignore */ }
    }
  } catch (e) { /* ignore sweep errors */ }
  if (removed) process.stdout.write(new Date().toISOString() + ' sweep removed ' + removed + ' expired blob(s)\n');
}
const sweepTimer = setInterval(sweep, 60000);
sweepTimer.unref();

server.listen(CFG.port, CFG.host, () => {
  const scheme = (CFG.tlsCert && CFG.tlsKey) ? 'https' : 'http';
  const port = server.address().port;
  process.stdout.write('Pairwise server on ' + scheme + '://' + CFG.host + ':' + port +
    ' store=' + CFG.store + ' maxBytes=' + CFG.maxBytes + ' maxTtl=' + CFG.maxTtl + 's\n');
  sweep();
});

export { server, CFG };
