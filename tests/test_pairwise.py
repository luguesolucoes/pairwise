"""Pairwise automated tests (store-and-forward architecture).

Runs the built dist/index.html served by the real Node backend (server/server.mjs) in
headless Chromium via Playwright:
  1. Unit tests of core cryptography, chunking, the stored-blob framing and the link format.
  2. End-to-end: the sender encrypts and uploads; a second browser opens the link, downloads
     and decrypts, and the SHA-256 of the original and reconstructed text must match.
  3. The sender page is CLOSED before the receiver opens the link, proving independence.
  4. once/TTL/delete semantics, the 64 MiB-class size limit, and that the key never reaches
     the server (checked against the server's own request log).

Usage:  python3 tests/test_pairwise.py [--quick]
"""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import urllib.error

from playwright.sync_api import sync_playwright

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
DIST = os.path.join(ROOT, 'dist', 'index.html')
SERVER = os.path.join(ROOT, 'server', 'server.mjs')
QUICK = '--quick' in sys.argv
RESULTS = []


def record(name, ok, detail=''):
    RESULTS.append((name, ok, detail))
    print(('PASS ' if ok else 'FAIL ') + name + ('  ' + detail if detail else ''), flush=True)


class Server:
    def __init__(self, max_bytes=64 * 1024 * 1024, max_ttl=86400):
        self.store = tempfile.mkdtemp(prefix='pw-store-')
        env = dict(os.environ)
        env.update({
            'PAIRWISE_PORT': '0', 'PAIRWISE_HOST': '127.0.0.1', 'PAIRWISE_STORE': self.store,
            'PAIRWISE_STATIC': DIST, 'PAIRWISE_MAX_BYTES': str(max_bytes), 'PAIRWISE_MAX_TTL': str(max_ttl),
        })
        self.proc = subprocess.Popen(['node', SERVER], stdout=subprocess.PIPE, text=True, env=env)
        self.log = []
        self.port = None
        import re
        line = self.proc.stdout.readline()
        # "Pairwise server on http://127.0.0.1:PORT store=..."
        m = re.search(r'://[^:/\s]+:(\d+)', line)
        if not m:
            raise RuntimeError('server did not start: ' + repr(line) + repr(self.proc.stdout.read()))
        self.port = int(m.group(1))
        threading.Thread(target=self._drain, daemon=True).start()

    def _drain(self):
        for l in self.proc.stdout:
            self.log.append(l.rstrip())

    @property
    def url(self):
        return 'http://localhost:%d' % self.port

    def requests(self):
        return [l for l in self.log if ' GET ' in l or ' POST ' in l or ' DELETE ' in l]

    def stop(self):
        try:
            self.proc.terminate()
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()


# --------------------------------------------------------------- unit tests
UNIT_JS = r"""
async () => {
  const out = [];
  const t = async (name, fn) => { try { const r = await fn(); out.push([name, r === true || r === undefined, r === true || r === undefined ? '' : String(r)]); } catch (e) { out.push([name, false, String(e && e.stack || e)]); } };
  const mustFail = async (fn) => { try { await fn(); return false; } catch (e) { return true; } };
  const enc = new TextEncoder(), dec = new TextDecoder();
  const tricky = 'ASCII\tline\r\nCRLF\n' + 'é ñ ü ß ' + '中文 日本語 한국어 ' + 'العربية עברית ' + 'é combining ' + '😀👩‍👩‍👧‍👦🏳️‍🌈 ' + '\u0000NUL  LS ﻿BOM ' + '𝔘𝔫𝔦𝔠𝔬𝔡𝔢';

  await t('base64url round trip (all lengths 0..64)', () => {
    for (let n = 0; n <= 64; n++) { const b = LT.rand(n); if (!LT.equalBytes(LT.unb64u(LT.b64u(b)), b)) return 'mismatch at ' + n; }
    return true;
  });

  await t('utf8Length matches TextEncoder', () => {
    for (const s of [tricky, '', 'a', '😀', tricky.repeat(50)]) if (LT.utf8Length(s) !== enc.encode(s).length) return 'mismatch';
    return true;
  });

  await t('countLines / lineIndex', () => {
    if (LT.countLines('') !== 0 || LT.countLines('a') !== 1 || LT.countLines('a\n') !== 2 || LT.countLines('\n\n') !== 3) return 'countLines wrong';
    return JSON.stringify(Array.from(LT.lineIndex('ab\ncd\n\nef'))) === '[0,3,6,7]' || 'lineIndex wrong';
  });

  await t('unpaired surrogate detection', () => LT.countUnpairedSurrogates('ok😀') === 0 && LT.countUnpairedSurrogates('a\uD800b\uDC00') === 2 || 'wrong');

  for (const cb of [5, 7, 13, 64, 1000]) {
    await t('chunking never splits code points (chunk ' + cb + ')', async () => {
      const s = tricky.repeat(20);
      const m = await LT.prepare(s, { chunkBytes: cb });
      const buf = new Uint8Array(cb); const d = new TextDecoder('utf-8', { fatal: true });
      let total = 0, outS = '';
      for (let i = 0; i < m.count; i++) { const c = LT.chunkBytesAt(s, m, i, buf); if (c.length > cb) return 'too big'; total += c.length; new TextDecoder('utf-8', { fatal: true }).decode(c); outS += d.decode(c, { stream: true }); }
      outS += d.decode();
      return (total === m.totalBytes && outS === s) || 'reassembly mismatch';
    });
  }

  await t('integrity digest changes with content', async () => {
    const a = await LT.prepare('hello world'); const b = await LT.prepare('hello worlx');
    return !LT.equalBytes(a.digest, b.digest) || 'digest unchanged';
  });

  await t('AES-GCM frame round trip + tamper/reorder/truncation/cross-session', async () => {
    const s = await LT.newSession();
    const f = await LT.sealFrame(s, LT.T_DATA, 7, 10, enc.encode('hello ' + tricky));
    const o = await LT.openFrame(s, f, 10);
    if (o.index !== 7 || dec.decode(o.plain) !== 'hello ' + tricky) return 'round trip failed';
    for (const pos of [LT.FRAME_HEADER, f.length - 1]) { const g = f.slice(); g[pos] ^= 1; if (!(await mustFail(() => LT.openFrame(s, g, 10)))) return 'tamper accepted'; }
    const g = f.slice(); new DataView(g.buffer).setUint32(1, 8); if (!(await mustFail(() => LT.openFrame(s, g, 10)))) return 'reorder accepted';
    if (!(await mustFail(() => LT.openFrame(s, f, 5)))) return 'wrong count accepted';
    const s2 = await LT.newSession(); if (!(await mustFail(() => LT.openFrame(s2, f, 10)))) return 'cross-session accepted';
    const s3 = await LT.openSession(s2.sid, s.key); if (!(await mustFail(() => LT.openFrame(s3, f, 10)))) return 'wrong sid accepted';
    return true;
  });

  await t('blob FrameSplitter reassembles frames and rejects corruption', async () => {
    const s = await LT.newSession();
    const frames = [];
    for (let i = 0; i < 5; i++) frames.push(await LT.sealFrame(s, LT.T_DATA, i, 5, enc.encode('chunk ' + i)));
    const parts = [LT.MAGIC];
    for (const f of frames) { parts.push(LT.u32be(f.length), f); }
    const blob = new Uint8Array(await new Blob(parts).arrayBuffer());
    // Feed the blob in awkward 7-byte slices; every frame must come back intact and in order.
    const sp = new LT.FrameSplitter(); const got = [];
    for (let i = 0; i < blob.length; i += 7) got.push(...sp.push(blob.subarray(i, i + 7)));
    sp.end();
    if (got.length !== 5) return 'got ' + got.length + ' frames';
    for (let i = 0; i < 5; i++) { const o = await LT.openFrame(s, got[i], 5); if (dec.decode(o.plain) !== 'chunk ' + i) return 'frame ' + i + ' wrong'; }
    // Wrong magic rejected.
    if (!(await mustFail(() => { const bad = new LT.FrameSplitter(); bad.push(enc.encode('XXXXyyyy')); }))) return 'bad magic accepted';
    // Truncated tail detected at end().
    const sp2 = new LT.FrameSplitter(); sp2.push(blob.subarray(0, blob.length - 3));
    if (!(await mustFail(() => sp2.end()))) return 'truncation not detected';
    return true;
  });

  await t('manifest encode/decode and validation', async () => {
    const m = await LT.prepare('abc');
    const o = LT.decodeManifest(LT.encodeManifest(m, 123));
    if (o.count !== m.count || o.bytes !== 3 || o.exp !== 123 || o.digest !== LT.hex(m.digest)) return 'fields lost';
    return await mustFail(() => LT.decodeManifest(new TextEncoder().encode('{"v":1,"count":-1}'))) || 'accepted bad manifest';
  });

  await t('retrieval link parse, and rejection of garbage', async () => {
    const s = await LT.newSession(); const id = LT.hex(LT.rand(16));
    const link = 'https://host.example/p/#' + LT.retrieveFragment(s, id);
    const p = LT.parseRetrieve(link);
    if (!LT.equalBytes(p.key, s.key) || !LT.equalBytes(p.sid, s.sid) || p.id !== id) return 'parse lost data';
    for (const bad of ['', 'hello', 'pw1b!x!y', '#pw1!a!b!c!d', '#pw1b!AAAA!BBBB!xyz', '#pw1b!' + LT.b64u(s.sid) + '!' + LT.b64u(s.key) + '!../etc']) {
      if (!(await mustFail(() => LT.parseRetrieve(bad)))) return 'accepted: ' + bad;
    }
    return true;
  });

  return out;
}
"""

E2E_SETUP_JS = r"""
async ([kind, size]) => {
  const parts = []; let len = 0, i = 0;
  const pad = (n, w) => String(n).padStart(w, '0');
  if (kind === 'log') { while (len < size) { const l = '2026-11-02T11:' + pad(i % 60, 2) + ':' + pad(i % 60, 2) + '.' + pad(i % 1000, 3) + 'Z INFO svc=gateway req=' + i.toString(16) + ' latency_ms=' + (i % 977) + ' path="/v1/items/' + i + '"'; parts.push(l); len += l.length + 1; i++; } }
  else if (kind === 'short-lines') { while (parts.length < size) { parts.push('row ' + i + '\t' + (i * 7919 % 100003)); i++; } }
  else if (kind === 'json') { const items = []; while (len < size) { const s = JSON.stringify({ id: i, name: 'Item ' + i, tags: ['a', 'ç', '中'], price: (i * 1.07).toFixed(2), nested: { ok: i % 2 === 0, note: 'line\nbreak "quoted" \\ back' } }, null, 2); items.push(s); len += s.length + 2; i++; } parts.push('[' + items.join(',\n') + ']'); }
  else if (kind === 'sql') { parts.push('BEGIN;'); while (len < size) { const l = "INSERT INTO orders (id, customer, note) VALUES (" + i + ", 'Cliente " + i + "', 'O''Brien; -- not a comment');"; parts.push(l); len += l.length + 1; i++; } parts.push('COMMIT;'); }
  else if (kind === 'unicode') { const samples = ['Português: ação, coração', '中文：你好，世界', '日本語：こんにちは', '한국어: 안녕하세요', 'العربية: مرحبا', 'עברית: שלום', 'Русский: Привет', 'Emoji: 😀 👩‍👩‍👧‍👦 🏳️‍🌈 🇧🇷', 'Math: 𝔘𝔫𝔦 ∑∫√∞', 'Combining: é ä', 'Controls:\tTAB\u0000NUL\u001BESC', 'Sep: LS NBSP﻿BOM', 'CRLF\r', '  spaces  ']; while (len < size) { const l = samples[i % samples.length] + ' #' + i; parts.push(l); len += l.length + 1; i++; } }
  const text = parts.join('\n');
  const ta = document.getElementById('input');
  if (text.length > 1000000 || text.includes('\r')) {
    const dt = new DataTransfer(); dt.setData('text/plain', text);
    ta.focus(); ta.dispatchEvent(new ClipboardEvent('paste', { clipboardData: dt, bubbles: true, cancelable: true }));
  } else { ta.value = text; ta.dispatchEvent(new Event('input', { bubbles: true })); }
  const h = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return { chars: text.length, lines: LT.countLines(text), bytes: LT.utf8Length(text), sha: LT.hex(new Uint8Array(h)), big: window.__pw.isBig() };
}
"""

HASH_RECEIVED_JS = r"""
async () => {
  const t = window.__pw.received();
  if (t === null) return null;
  const h = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(t));
  return { chars: t.length, sha: LT.hex(new Uint8Array(h)), mem: performance.memory ? performance.memory.usedJSHeapSize : null };
}
"""


def recv_url(link, base):
    # link is "<base>/#pw1b!..."; add ?test=1 before the fragment so the test hook loads.
    frag = link.split('#', 1)[1]
    return base + '/?test=1#' + frag


def send_and_get_link(page, server, kind, size, once=True):
    info = page.evaluate(E2E_SETUP_JS, [kind, size])
    page.wait_for_function("!document.getElementById('btn-send').disabled", timeout=60000)
    if not once:
        page.uncheck('#once')
    page.click('#btn-send')
    page.wait_for_function("document.getElementById('send-link').value.includes('#pw1b!')", timeout=180000)
    return info, page.input_value('#send-link')


def e2e_case(browser, server, name, kind, size, timeout_s=300, close_sender=False):
    ctx_s = browser.new_context(bypass_csp=True)
    s = ctx_s.new_page()
    reqs = []
    s.on('request', lambda r: reqs.append(r.url))
    try:
        s.goto(server.url + '/?test=1')
        t0 = time.time()
        info, link = send_and_get_link(s, server, kind, size)
        t_up = time.time() - t0
        mem_s = s.evaluate('performance.memory ? performance.memory.usedJSHeapSize : null')
        if close_sender:
            ctx_s.close(); ctx_s = None
        ctx_r = browser.new_context(bypass_csp=True)
        r = ctx_r.new_page()
        rreqs = []
        r.on('request', lambda rq: rreqs.append(rq.url))
        t1 = time.time()
        r.goto(recv_url(link, server.url))
        r.wait_for_selector('#recv-result:not([hidden])', timeout=timeout_s * 1000)
        t_down = time.time() - t1
        got = r.evaluate(HASH_RECEIVED_JS)
        mem_r = got['mem'] if got else 0
        ok = got and got['sha'] == info['sha'] and got['chars'] == info['chars']
        # No request URL (sender upload or receiver download) may contain key material.
        key_b64 = link.split('#', 1)[1].split('!')[2]
        leaked = any(key_b64 in u for u in reqs + rreqs)
        detail = ('%s chars, %s lines, %.1f MiB | up+enc %.1fs, down+dec %.1fs | heap S %.0f / R %.0f MiB | link %d chars%s'
                  % (format(info['chars'], ','), format(info['lines'], ','), info['bytes'] / 1048576, t_up, t_down,
                     (mem_s or 0) / 1048576, (mem_r or 0) / 1048576, len(link), ', sender closed first' if close_sender else ''))
        record('e2e ' + name, bool(ok) and not leaked, detail + ('' if not leaked else ' KEY LEAKED IN URL'))
        ctx_r.close()
    except Exception as e:
        record('e2e ' + name, False, repr(e)[:400])
    finally:
        if ctx_s:
            ctx_s.close()


def once_case(browser, server):
    """once=1: first open succeeds, second open finds nothing. once=0: opens twice."""
    for once, label in [(True, 'once=1 deletes after first download'), (False, 'once=0 allows a second open')]:
        ctx_s = browser.new_context(bypass_csp=True); s = ctx_s.new_page()
        try:
            s.goto(server.url + '/?test=1')
            info, link = send_and_get_link(s, server, 'log', 200000, once=once)
            ctx_s.close(); ctx_s = None
            # First open
            c1 = browser.new_context(bypass_csp=True); p1 = c1.new_page()
            p1.goto(recv_url(link, server.url))
            p1.wait_for_selector('#recv-result:not([hidden])', timeout=60000)
            g1 = p1.evaluate(HASH_RECEIVED_JS)
            c1.close()
            # Second open
            c2 = browser.new_context(bypass_csp=True); p2 = c2.new_page()
            p2.goto(recv_url(link, server.url))
            if once:
                p2.wait_for_selector('#recv-issue:not([hidden])', timeout=30000)
                second_ok = 'no longer exists' in (p2.text_content('#recv-issue') or '')
            else:
                p2.wait_for_selector('#recv-result:not([hidden])', timeout=60000)
                g2 = p2.evaluate(HASH_RECEIVED_JS)
                second_ok = g2 and g2['sha'] == info['sha']
            c2.close()
            record(label, g1 and g1['sha'] == info['sha'] and second_ok, 'first matched=%s, second as expected=%s' % (bool(g1 and g1['sha'] == info['sha']), bool(second_ok)))
        except Exception as e:
            record(label, False, repr(e)[:300])
        finally:
            if ctx_s:
                ctx_s.close()


def delete_case(browser, server):
    """Delete now removes the blob; opening the link then reports it is gone."""
    ctx_s = browser.new_context(bypass_csp=True); s = ctx_s.new_page()
    try:
        s.goto(server.url + '/?test=1')
        info, link = send_and_get_link(s, server, 'log', 100000, once=False)
        s.click('#btn-destroy')
        s.wait_for_selector('#send-result', state='hidden', timeout=10000)
        c = browser.new_context(bypass_csp=True); p = c.new_page()
        p.goto(recv_url(link, server.url))
        p.wait_for_selector('#recv-issue:not([hidden])', timeout=30000)
        issue_txt = p.text_content('#recv-issue') or ''
        gone = 'no longer exists' in issue_txt
        c.close()
        record('delete now removes the blob from the server', gone, 'receiver saw: ' + issue_txt[:80])
    except Exception as e:
        record('delete now removes the blob from the server', False, repr(e)[:300])
    finally:
        ctx_s.close()


def size_limit_case():
    """A separate server with a 1 MiB cap rejects a 2 MiB upload with 413, no browser involved."""
    srv = Server(max_bytes=1024 * 1024)
    try:
        body = b'x' * (2 * 1024 * 1024)
        req = urllib.request.Request(srv.url + '/api/blob?ttl=300', data=body, method='POST',
                                     headers={'Content-Type': 'application/octet-stream'})
        status = None
        try:
            urllib.request.urlopen(req, timeout=10)
        except urllib.error.HTTPError as e:
            status = e.code
        # A small upload on the same server still works.
        ok_req = urllib.request.Request(srv.url + '/api/blob?ttl=300', data=b'hello-small-blob', method='POST',
                                        headers={'Content-Type': 'application/octet-stream'})
        small = json.loads(urllib.request.urlopen(ok_req, timeout=10).read())
        record('server rejects oversize upload (413) but accepts small', status == 413 and bool(small.get('id')),
               'oversize status=%s, small id=%s' % (status, bool(small.get('id'))))
    except Exception as e:
        record('server rejects oversize upload (413) but accepts small', False, repr(e)[:300])
    finally:
        srv.stop()


def key_privacy_case(server):
    """The server's own request log must never contain any key material, only ids and paths."""
    reqs = server.requests()
    # Every API line references /api/blob or /api/blob/<32 hex>; never a base64url key (>=43 chars).
    import re
    suspicious = [l for l in reqs if re.search(r'[A-Za-z0-9_-]{43,}', l.split(' -> ')[0])]
    paths = [l.split(' ')[3] for l in reqs if len(l.split(' ')) > 3]
    record('server request log never contains key material', not suspicious and len(reqs) > 0,
           '%d API requests logged; sample paths: %s' % (len(reqs), ', '.join(sorted(set(paths))[:5])))


def main():
    server = Server()
    print('Server:', server.url, 'store', server.store, flush=True)
    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path='/usr/bin/google-chrome' if os.path.exists('/usr/bin/google-chrome') else None)
        print('Browser:', browser.version, flush=True)
        page = browser.new_page()
        errors = []
        page.on('pageerror', lambda e: errors.append(str(e)))
        page.on('console', lambda m: m.type == 'error' and errors.append(m.text))
        page.goto(server.url + '/?test=1')
        page.wait_for_timeout(500)
        record('page loads without console errors or CSP violations', not errors, '; '.join(errors)[:300])
        for name, ok, detail in page.evaluate(UNIT_JS):
            record('unit ' + name, ok, detail)
        page.close()

        # The headline requirement: sender closes the page, receiver still gets it.
        e2e_case(browser, server, 'sender closed before receiver opens (10 MB)', 'log', 10 * 1048576, close_sender=True)

        cases = [('small plain text', 'log', 50000), ('Unicode with CRLF/NUL/emoji', 'unicode', 200000)]
        if not QUICK:
            cases += [
                ('1 MB log', 'log', 1048576), ('10 MB log', 'log', 10 * 1048576),
                ('25 MB log', 'log', 25 * 1048576), ('50 MB log', 'log', 50 * 1048576),
                ('1,000,000 lines', 'short-lines', 1000000), ('2,000,000 lines', 'short-lines', 2000000),
                ('large JSON (~20 MB)', 'json', 20 * 1048576), ('large SQL (~15 MB)', 'sql', 15 * 1048576),
                ('multilingual Unicode (~7 MB)', 'unicode', 7 * 1048576 // 2),
            ]
        for name, kind, size in cases:
            e2e_case(browser, server, name, kind, size)

        once_case(browser, server)
        delete_case(browser, server)
        key_privacy_case(server)
        browser.close()
    size_limit_case()
    server.stop()

    failed = [r for r in RESULTS if not r[1]]
    print('\n%d passed, %d failed' % (len(RESULTS) - len(failed), len(failed)))
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'results-chromium.json'), 'w') as f:
        json.dump([{'test': n, 'pass': o, 'detail': d} for n, o, d in RESULTS], f, indent=2, ensure_ascii=False)
    sys.exit(1 if failed else 0)


if __name__ == '__main__':
    main()
