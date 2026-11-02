// Build: inline the QR library and sources into one static index.html with a strict CSP.
// The page is served by server/server.mjs; the API is same-origin, so connect-src is 'self'.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { minify } from 'terser';

const read = (p) => readFileSync(new URL(p, import.meta.url), 'utf8');
const min = async (code, mangle = true) => (await minify(code, { compress: true, mangle, format: { comments: false } })).code;

const parts = {
  __QRGEN__: await min(read('./node_modules/qrcode-generator/qrcode.js')),
  __CORE__: read('./src/core.js'),
  __NET__: read('./src/net.js'),
  __UI__: read('./src/ui.js'),
};
for (const [k, v] of Object.entries(parts)) {
  if (v.includes('</script')) throw new Error(k + ' contains a closing script tag');
}
const hashes = Object.values(parts).map((c) => "'sha256-" + createHash('sha256').update(c, 'utf8').digest('base64') + "'");
const csp = [
  "default-src 'none'",
  'script-src ' + hashes.join(' '),
  "style-src 'unsafe-inline'",
  'img-src data: blob:',
  "connect-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
].join('; ');

let html = read('./src/index.template.html');
const swap = (s, k, v) => { const i = s.indexOf(k); if (i < 0) throw new Error('missing ' + k); return s.slice(0, i) + v + s.slice(i + k.length); };
html = swap(html, '__CSP__', csp);
for (const [k, v] of Object.entries(parts)) html = swap(html, k, v);
mkdirSync(new URL('./dist/', import.meta.url), { recursive: true });
writeFileSync(new URL('./dist/index.html', import.meta.url), html);
console.log('dist/index.html', html.length, 'bytes');
