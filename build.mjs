// Build: inline libraries and sources into one static index.html with a strict CSP.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { minify } from 'terser';

const read = (p) => readFileSync(new URL(p, import.meta.url), 'utf8');
const min = async (code, mangle = true) => (await minify(code, { compress: true, mangle, format: { comments: false } })).code;

const parts = {
  __QRGEN__: await min(read('./node_modules/qrcode-generator/qrcode.js')),
  __JSQR__: await min(read('./node_modules/jsqr/dist/jsQR.js')),
  __CORE__: read('./src/core.js'),
  __SESSION__: read('./src/session.js'),
  __RELAY__: read('./src/relay.js'),
  __UI__: read('./src/ui.js'),
};
for (const [k, v] of Object.entries(parts)) {
  if (v.includes('</script')) throw new Error(k + ' contains a closing script tag');
}
// Relay origins for the CSP come from the relay list in src/relay.js.
const relayList = [...read('./src/relay.js').matchAll(/url: '(wss:\/\/[^']+)', label: '([^']+)'/g)];
if (!relayList.length) throw new Error('no relays found in relay.js');
const relayOrigins = relayList.map((m) => { const u = new URL(m[1]); return 'wss://' + u.host; });
const relayLabels = relayList.map((m) => m[2]).join(', ');
const hashes = Object.values(parts).map((c) => "'sha256-" + createHash('sha256').update(c, 'utf8').digest('base64') + "'");
const csp = [
  "default-src 'none'",
  'script-src ' + hashes.join(' '),
  "style-src 'unsafe-inline'",
  'img-src data: blob:',
  'media-src blob: mediastream:',
  'connect-src ' + relayOrigins.join(' '),
  "base-uri 'none'",
  "form-action 'none'",
].join('; ');

let html = read('./src/index.template.html');
const swap = (s, k, v) => { const i = s.indexOf(k); if (i < 0) throw new Error('missing ' + k); return s.slice(0, i) + v + s.slice(i + k.length); };
html = swap(html, '__CSP__', csp);
html = html.split('__RELAYS__').join(relayLabels);
for (const [k, v] of Object.entries(parts)) html = swap(html, k, v);
mkdirSync(new URL('./dist/', import.meta.url), { recursive: true });
writeFileSync(new URL('./dist/index.html', import.meta.url), html);
writeFileSync(new URL('./index.html', import.meta.url), html); // root copy served by GitHub Pages
console.log('dist/index.html', html.length, 'bytes');
