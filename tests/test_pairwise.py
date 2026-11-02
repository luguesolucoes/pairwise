"""Pairwise automated tests.

Runs the built dist/index.html in real Chromium (Google Chrome) via Playwright:
  1. Unit tests of core cryptography, chunking, integrity and signaling compaction.
  2. End-to-end transfers between two isolated browser contexts over a real WebRTC
     data channel, driven through the UI (paste -> encrypt & pair -> answer -> verify).
  3. Resume after a dropped connection, session end, and network-request auditing.

Usage:  python3 tests/test_pairwise.py [--quick] [--browser chromium|webkit]
"""
import http.server
import json
import os
import socketserver
import sys
import threading
import time

from playwright.sync_api import sync_playwright

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'dist')
QUICK = '--quick' in sys.argv
BROWSER = 'webkit' if '--browser' in sys.argv and sys.argv[sys.argv.index('--browser') + 1] == 'webkit' else 'chromium'

REQUEST_LOG = []


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **k):
        super().__init__(*a, directory=ROOT, **k)

    def log_message(self, fmt, *args):
        REQUEST_LOG.append(self.requestline)


def serve():
    socketserver.TCPServer.allow_reuse_address = True
    srv = socketserver.ThreadingTCPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, 'http://localhost:%d/index.html?test=1' % srv.server_address[1]


RESULTS = []


def record(name, ok, detail=''):
    RESULTS.append((name, ok, detail))
    print(('PASS ' if ok else 'FAIL ') + name + ('  ' + detail if detail else ''), flush=True)


# --------------------------------------------------------------- unit tests
UNIT_JS = r"""
async () => {
  const out = [];
  const t = async (name, fn) => { try { const r = await fn(); out.push([name, r === true || r === undefined, r === true || r === undefined ? '' : String(r)]); } catch (e) { out.push([name, false, String(e && e.stack || e)]); } };
  const enc = new TextEncoder(), dec = new TextDecoder();

  await t('base64url round trip (all lengths 0..64)', () => {
    for (let n = 0; n <= 64; n++) { const b = LT.rand(n); if (!LT.equalBytes(LT.unb64u(LT.b64u(b)), b)) return 'mismatch at ' + n; }
    try { LT.unb64u('ab+/'); return 'accepted non-url alphabet'; } catch (e) {}
    return true;
  });

  const tricky = 'ASCII\tline\r\nCRLF\n' + 'é ñ ü ß ' + '中文 日本語 한국어 ' + 'العربية עברית ' + 'é combining ' + '😀👩‍👩‍👧‍👦🏳️‍🌈 ' + '\u0000NUL  LS ﻿BOM ' + '𝔘𝔫𝔦𝔠𝔬𝔡𝔢';

  await t('utf8Length matches TextEncoder', () => {
    for (const s of [tricky, '', 'a', '😀', tricky.repeat(50)]) if (LT.utf8Length(s) !== enc.encode(s).length) return 'mismatch for ' + JSON.stringify(s.slice(0, 20));
    return true;
  });

  await t('countLines / lineIndex', () => {
    if (LT.countLines('') !== 0 || LT.countLines('a') !== 1 || LT.countLines('a\n') !== 2 || LT.countLines('\n\n') !== 3) return 'countLines wrong';
    const idx = LT.lineIndex('ab\ncd\n\nef');
    return JSON.stringify(Array.from(idx)) === '[0,3,6,7]' || 'lineIndex ' + Array.from(idx);
  });

  await t('unpaired surrogate detection', () => {
    return LT.countUnpairedSurrogates('ok😀') === 0 && LT.countUnpairedSurrogates('a\uD800b\uDC00') === 2 && LT.countUnpairedSurrogates('\uD83D') === 1 || 'wrong count';
  });

  for (const cb of [4, 5, 7, 13, 64, 1000]) {
    await t('chunking never splits code points (chunk ' + cb + ' bytes)', async () => {
      const s = tricky.repeat(20);
      const m = await LT.prepare(s, { chunkBytes: cb });
      const buf = new Uint8Array(cb);
      const d = new TextDecoder('utf-8', { fatal: true });
      let total = 0, outS = '';
      for (let i = 0; i < m.count; i++) {
        const c = LT.chunkBytesAt(s, m, i, buf);
        if (c.length > cb) return 'chunk too big';
        total += c.length;
        new TextDecoder('utf-8', { fatal: true }).decode(c); // each chunk is valid UTF-8 on its own
        outS += d.decode(c, { stream: true });
      }
      outS += d.decode();
      if (total !== m.totalBytes || total !== enc.encode(s).length) return 'byte total mismatch';
      return outS === s || 'reassembly mismatch';
    });
  }

  await t('integrity digest equals receiver-side hash chain', async () => {
    const s = tricky.repeat(3000);
    const m = await LT.prepare(s);
    let h = new Uint8Array(32); const buf = new Uint8Array(m.chunkBytes);
    for (let i = 0; i < m.count; i++) h = await LT.chainStep(h, LT.chunkBytesAt(s, m, i, buf).slice());
    const d = await LT.finalDigest(h, m.totalBytes, m.count);
    if (!LT.equalBytes(d, m.digest)) return 'digest mismatch';
    const m2 = await LT.prepare(s.slice(0, -1) + 'X');
    return !LT.equalBytes(m2.digest, m.digest) || 'digest did not change';
  });

  await t('empty text prepares to zero chunks', async () => { const m = await LT.prepare(''); return m.count === 0 && m.totalBytes === 0 || 'not empty'; });

  await t('AES-GCM frame round trip', async () => {
    const s = await LT.newSession();
    const p = enc.encode('hello ' + tricky);
    const f = await LT.sealFrame(s, LT.T_DATA, 7, 10, p);
    const o = await LT.openFrame(s, f, 10);
    return o.index === 7 && o.type === LT.T_DATA && dec.decode(o.plain) === dec.decode(p) || 'round trip failed';
  });

  const mustFail = async (fn) => { try { await fn(); return false; } catch (e) { return true; } };

  await t('tampered ciphertext is rejected', async () => {
    const s = await LT.newSession();
    const f = await LT.sealFrame(s, LT.T_DATA, 0, 1, enc.encode('secret'));
    for (const pos of [LT.FRAME_HEADER, f.length - 1, f.length - 17]) { const g = f.slice(); g[pos] ^= 1; if (!(await mustFail(() => LT.openFrame(s, g, 1)))) return 'accepted tamper at ' + pos; }
    return true;
  });

  await t('reordered chunk (index rewritten) is rejected', async () => {
    const s = await LT.newSession();
    const f = await LT.sealFrame(s, LT.T_DATA, 3, 10, enc.encode('x'));
    const g = f.slice(); new DataView(g.buffer).setUint32(1, 4);
    return await mustFail(() => LT.openFrame(s, g, 10)) || 'accepted moved frame';
  });

  await t('truncation attack (different chunk count) is rejected', async () => {
    const s = await LT.newSession();
    const f = await LT.sealFrame(s, LT.T_DATA, 0, 10, enc.encode('x'));
    return await mustFail(() => LT.openFrame(s, f, 5)) || 'accepted wrong count';
  });

  await t('replay into another session is rejected', async () => {
    const a = await LT.newSession(), b = await LT.newSession();
    const f = await LT.sealFrame(a, LT.T_DATA, 0, 1, enc.encode('x'));
    if (!(await mustFail(() => LT.openFrame(b, f, 1)))) return 'cross-session accepted';
    const b2 = await LT.openSession(b.sid, a.key); // right key, wrong session id -> different derived key + AAD
    return await mustFail(() => LT.openFrame(b2, f, 1)) || 'wrong sid accepted';
  });

  await t('manifest frame type cannot be confused with data', async () => {
    const s = await LT.newSession();
    const f = await LT.sealFrame(s, LT.T_DATA, 0, 0, enc.encode('{}'));
    const g = f.slice(); g[0] = LT.T_MANIFEST;
    return await mustFail(() => LT.openFrame(s, g, 0)) || 'type confusion accepted';
  });

  await t('nonces unique across types and indexes', async () => {
    const s = await LT.newSession();
    const seen = new Set();
    for (const type of [LT.T_DATA, LT.T_MANIFEST]) for (let i = 0; i < 2000; i++) {
      // Same plaintext, different (type,index): ciphertexts must all differ.
      const f = await LT.sealFrame(s, type, i, 0, new Uint8Array(16));
      const k = LT.b64u(f.subarray(LT.FRAME_HEADER));
      if (seen.has(k)) return 'repeat at ' + type + '/' + i;
      seen.add(k);
    }
    return true;
  });

  await t('key auth: HMAC challenge accepts right key, rejects wrong key', async () => {
    const a = await LT.newSession(); const b = await LT.newSession();
    const n = LT.rand(16);
    const tag = await LT.authTag(a, n);
    return (await LT.authVerify(a, n, tag)) && !(await LT.authVerify(b, n, tag)) && !(await LT.authVerify(a, LT.rand(16), tag)) || 'auth wrong';
  });

  await t('manifest encode/decode and validation', async () => {
    const m = await LT.prepare('abc');
    const o = LT.decodeManifest(LT.encodeManifest(m, 123));
    if (o.count !== m.count || o.bytes !== 3 || o.exp !== 123 || o.digest !== LT.hex(m.digest)) return 'fields lost';
    return await mustFail(() => LT.decodeManifest(enc.encode('{"v":1,"count":-1}'))) || 'accepted bad manifest';
  });

  await t('compact SDP survives a real offer/answer and connects', async () => {
    const a = new RTCPeerConnection(), b = new RTCPeerConnection();
    const dc = a.createDataChannel('t');
    const gather = (pc) => new Promise((r) => { if (pc.iceGatheringState === 'complete') r(); pc.onicegatheringstatechange = () => pc.iceGatheringState === 'complete' && r(); setTimeout(r, 4000); });
    await a.setLocalDescription(await a.createOffer()); await gather(a);
    const offer = LT.compactSdp(a.localDescription.sdp);
    await b.setRemoteDescription({ type: 'offer', sdp: LT.expandSdp(offer) });
    await b.setLocalDescription(await b.createAnswer()); await gather(b);
    const answer = LT.compactSdp(b.localDescription.sdp);
    await a.setRemoteDescription({ type: 'answer', sdp: LT.expandSdp(answer) });
    const got = await new Promise((res) => {
      b.ondatachannel = (e) => { e.channel.onmessage = (m) => res(m.data); };
      dc.onopen = () => dc.send('ping');
      setTimeout(() => res(null), 10000);
    });
    a.close(); b.close();
    return got === 'ping' || 'channel did not deliver (offer ' + offer.length + ' chars)';
  });

  await t('CSP blocks HTTP requests from the page (connect-src none)', async () => {
    try { await fetch(location.href, { method: 'POST', body: 'x' }); return 'fetch was allowed'; } catch (e) { return true; }
  });

  await t('offer/answer codes: parse, size, and reject garbage', async () => {
    const s = await LT.newSession();
    const compact = 'abcd~' + 'p'.repeat(24) + '~' + LT.b64u(LT.rand(32)) + '~x~262144~h,1a2b3c4d-1111-2222-3333-444455556666.local,54321~s,203.0.113.7,61000';
    const link = 'https://example.org/p/#' + LT.offerFragment(s, compact);
    const o = LT.parseOffer(link);
    if (!LT.equalBytes(o.key, s.key) || !LT.equalBytes(o.sid, s.sid)) return 'parse lost data';
    const a = LT.parseAnswer(LT.answerCode(s.sid, compact));
    if (!LT.equalBytes(a.sid, s.sid)) return 'answer lost sid';
    for (const bad of ['', 'hello', 'pw1!x!y!z', link.replace('pw1!', 'pw2!'), 'pwa1!AAAA!' + compact]) {
      if (!(await mustFail(() => LT.parseOffer(bad)))) return 'offer accepted: ' + bad.slice(0, 30);
    }
    if (!(await mustFail(() => LT.parseAnswer('pwa1!' + LT.b64u(s.sid) + '!a~b')))) return 'answer accepted garbage';
    if (!(await mustFail(() => LT.expandSdp(compact.replace('54321', '54321\r\na=evil'))))) return 'injection accepted';
    return true;
  });

  return out;
}
"""

E2E_SETUP_JS = r"""
async ([kind, size]) => {
  // Generate test text inside the page (avoids pushing 50 MB through the test driver).
  const parts = [];
  let len = 0, i = 0;
  const target = size;
  const pad = (n, w) => String(n).padStart(w, '0');
  if (kind === 'log') {
    while (len < target) { const l = '2026-11-02T11:' + pad(i % 60, 2) + ':' + pad(i % 60, 2) + '.' + pad(i % 1000, 3) + 'Z INFO  svc=gateway req=' + i.toString(16) + ' latency_ms=' + (i % 977) + ' path="/v1/items/' + i + '"'; parts.push(l); len += l.length + 1; i++; }
  } else if (kind === 'short-lines') {
    while (parts.length < target) { parts.push('row ' + i + '\t' + (i * 7919 % 100003)); i++; }
  } else if (kind === 'json') {
    const items = [];
    while (len < target) { const o = { id: i, name: 'Item ' + i, tags: ['a', 'b', 'ç', '中'], price: (i * 1.07).toFixed(2), nested: { ok: i % 2 === 0, note: 'line\nbreak "quoted" \\ backslash' } }; const s = JSON.stringify(o, null, 2); items.push(s); len += s.length + 2; i++; }
    parts.push('[' + items.join(',\n') + ']');
  } else if (kind === 'sql') {
    parts.push('BEGIN;');
    while (len < target) { const l = "INSERT INTO orders (id, customer, note, amount) VALUES (" + i + ", 'Cliente " + i + "', 'O''Brien; -- not a comment', " + (i % 10000) / 100 + ");"; parts.push(l); len += l.length + 1; i++; }
    parts.push('COMMIT;');
  } else if (kind === 'unicode') {
    const samples = ['Português: ação, coração, pão', '中文：你好，世界', '日本語：こんにちは世界', '한국어: 안녕하세요', 'العربية: مرحبا بالعالم', 'עברית: שלום עולם', 'Ελληνικά: Γειά σου Κόσμε', 'Русский: Привет, мир', 'हिन्दी: नमस्ते दुनिया', 'Emoji: 😀 👩‍👩‍👧‍👦 🏳️‍🌈 🇧🇷 🇵🇹', 'Math: 𝔘𝔫𝔦𝔠𝔬𝔡𝔢 ∑∫√∞', 'Combining: é ä ñ', 'Controls:\tTAB\u0000NUL\u000BVT\u001BESC', 'Separators: LS PS NBSP﻿BOM', 'CRLF line\r', '    leading and trailing spaces    '];
    while (len < target) { const l = samples[i % samples.length] + ' #' + i; parts.push(l); len += l.length + 1; i++; }
  }
  const text = parts.join(kind === 'unicode' && 0 ? '\r\n' : '\n');
  window.__orig = text;
  const ta = document.getElementById('input');
  if (text.length > 1000000 || text.includes('\r')) {
    const dt = new DataTransfer(); dt.setData('text/plain', text);
    ta.focus();
    ta.dispatchEvent(new ClipboardEvent('paste', { clipboardData: dt, bubbles: true, cancelable: true }));
  } else {
    // Synthetic paste events have no default action, so small text is typed in directly.
    ta.value = text; ta.dispatchEvent(new Event('input', { bubbles: true }));
  }
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


def pair(sender, receiver, timeout=120000):
    sender.wait_for_function("document.getElementById('send-link').value.includes('#pw1!')", timeout=timeout)
    link = sender.input_value('#send-link')
    receiver.evaluate("document.getElementById('answer-out').dataset.prev = document.getElementById('answer-out').value")
    receiver.fill('#offer-input', link)
    receiver.click('#btn-offer-go')
    receiver.wait_for_function("(() => { const a = document.getElementById('answer-out'); return a.value.startsWith('pwa1!') && a.value !== a.dataset.prev; })()", timeout=30000)
    answer = receiver.input_value('#answer-out')
    sender.fill('#answer-input', answer)
    sender.click('#btn-connect')
    return link, answer


def e2e_case(browser, url, name, kind, size, timeout_s=300):
    ctx_s = browser.new_context(bypass_csp=True)
    ctx_r = browser.new_context(bypass_csp=True)
    s = ctx_s.new_page()
    r = ctx_r.new_page()
    reqs = []
    for p in (s, r):
        p.on('request', lambda req: reqs.append(req.url))
    try:
        s.goto(url)
        r.goto(url)
        r.click('#tab-recv')
        t0 = time.time()
        info = s.evaluate(E2E_SETUP_JS, [kind, size])
        t_gen = time.time() - t0
        s.wait_for_function("!document.getElementById('btn-prepare').disabled", timeout=60000)
        shown_chars = s.text_content('#st-chars').replace(',', '')
        if int(shown_chars) != info['chars']:
            raise AssertionError('character count shown %s != %s' % (shown_chars, info['chars']))
        t1 = time.time()
        s.click('#btn-prepare')
        link, answer = pair(s, r)
        t_pair = time.time() - t1
        t2 = time.time()
        r.wait_for_selector('#recv-result:not([hidden])', timeout=timeout_s * 1000)
        s.wait_for_function("document.getElementById('send-state').textContent.startsWith('verified')", timeout=30000)
        t_xfer = time.time() - t2
        got = r.evaluate(HASH_RECEIVED_JS)
        mem_s = s.evaluate('performance.memory ? performance.memory.usedJSHeapSize : null')
        ok = got and got['sha'] == info['sha'] and got['chars'] == info['chars']
        external = [u for u in reqs if not u.startswith(url.split('/index.html')[0])]
        detail = ('%s chars, %s lines, %.1f MiB UTF-8, big-view=%s | prepare+pair %.1fs, transfer+verify %.1fs (%.1f MiB/s) | heap sender %.0f MiB, receiver %.0f MiB | offer QR payload %d chars, answer %d chars'
                  % (format(info['chars'], ','), format(info['lines'], ','), info['bytes'] / 1048576, info['big'], t_pair, t_xfer,
                     info['bytes'] / 1048576 / max(t_xfer, 0.001), (mem_s or 0) / 1048576, (got['mem'] or 0) / 1048576 if got else 0,
                     len(link), len(answer)))
        record('e2e ' + name, bool(ok) and not external, detail + ('' if not external else ' EXTERNAL REQUESTS: %s' % external))
    except Exception as e:
        record('e2e ' + name, False, repr(e)[:400])
    finally:
        ctx_s.close()
        ctx_r.close()


def resume_case(browser, url):
    ctx_s, ctx_r = browser.new_context(bypass_csp=True), browser.new_context(bypass_csp=True)
    s, r = ctx_s.new_page(), ctx_r.new_page()
    try:
        s.goto(url); r.goto(url); r.click('#tab-recv')
        info = s.evaluate(E2E_SETUP_JS, ['log', 25 * 1048576])
        s.click('#btn-prepare')
        pair(s, r)
        r.wait_for_function("parseInt(document.getElementById('rp-chunk').textContent.replace(/,/g,''))>120", timeout=120000)
        s.evaluate('window.__pw.dropLink()')
        s.wait_for_selector('#send-resume:not([hidden])', timeout=30000)
        r.wait_for_selector('#recv-connect:not([hidden])', timeout=30000)
        at = int(r.text_content('#rp-chunk').replace(',', ''))
        s.click('#btn-new-code')
        s.wait_for_selector('#send-pair:not([hidden])', timeout=30000)
        pair(s, r)
        r.wait_for_selector('#recv-result:not([hidden])', timeout=300000)
        got = r.evaluate(HASH_RECEIVED_JS)
        logtxt = s.text_content('#log')
        resumed = 'resuming at chunk' in logtxt
        record('resume after dropped connection', got['sha'] == info['sha'] and resumed and at > 0,
               'dropped at chunk %d; sender log shows resume=%s' % (at, resumed))
    except Exception as e:
        record('resume after dropped connection', False, repr(e)[:300] + ' | SENDER LOG: ' + (s.text_content('#log') or '')[-900:] + ' | RECEIVER LOG: ' + (r.text_content('#log') or '')[-900:])
    finally:
        ctx_s.close(); ctx_r.close()


def end_session_case(browser, url):
    ctx_s, ctx_r = browser.new_context(bypass_csp=True), browser.new_context(bypass_csp=True)
    s, r = ctx_s.new_page(), ctx_r.new_page()
    try:
        s.goto(url); r.goto(url); r.click('#tab-recv')
        s.evaluate(E2E_SETUP_JS, ['log', 200000])
        s.click('#btn-prepare')
        s.wait_for_function("document.getElementById('send-link').value.includes('#pw1!')")
        link = s.input_value('#send-link')
        s.click('#btn-send-end')
        cleared = s.input_value('#send-link') == '' and s.is_hidden('#send-pair') and not s.is_disabled('#btn-prepare')
        editable = not s.evaluate("document.getElementById('input').readOnly")
        # The receiver can still build an answer from the stale code, but nothing on the sender
        # side accepts it any more, so no channel opens.
        r.fill('#offer-input', link); r.click('#btn-offer-go')
        r.wait_for_function("document.getElementById('answer-out').value.startsWith('pwa1!')", timeout=30000)
        time.sleep(3)
        no_channel = r.is_hidden('#recv-progress')
        record('manual session end discards session', cleared and editable and no_channel,
               'UI cleared=%s, editor unlocked=%s, stale code opened no channel=%s' % (cleared, editable, no_channel))
    except Exception as e:
        record('manual session end discards session', False, repr(e)[:400])
    finally:
        ctx_s.close(); ctx_r.close()


def fragment_case(browser, url):
    """Opening the QR link directly: key stays out of server requests and is removed from the address bar."""
    ctx_s, ctx_r = browser.new_context(bypass_csp=True), browser.new_context(bypass_csp=True)
    s, r = ctx_s.new_page(), ctx_r.new_page()
    try:
        s.goto(url)
        info = s.evaluate(E2E_SETUP_JS, ['unicode', 300000])
        s.click('#btn-prepare')
        s.wait_for_function("document.getElementById('send-link').value.includes('#pw1!')")
        link = s.input_value('#send-link')
        key = link.split('#', 1)[1].split('!')[2]
        before = len(REQUEST_LOG)
        # The real link has no query string; add ?test=1 so the test hook loads.
        r.goto(url + '#' + link.split('#', 1)[1])
        r.wait_for_function("document.getElementById('answer-out').value.startsWith('pwa1!')", timeout=30000)
        leaked = any(key in line for line in REQUEST_LOG[before:])
        url_clean = '#' not in r.url
        s.fill('#answer-input', r.input_value('#answer-out')); s.click('#btn-connect')
        r.wait_for_selector('#recv-result:not([hidden])', timeout=60000)
        got = r.evaluate(HASH_RECEIVED_JS)
        record('QR link flow: key never reaches the server, removed from address bar',
               (not leaked) and url_clean and got['sha'] == info['sha'],
               'server saw key=%s, address bar clean=%s, server request lines: %s' % (leaked, url_clean, REQUEST_LOG[before:]))
    except Exception as e:
        record('QR link flow: key never reaches the server, removed from address bar', False, repr(e)[:400])
    finally:
        ctx_s.close(); ctx_r.close()


def main():
    srv, url = serve()
    with sync_playwright() as p:
        if BROWSER == 'webkit':
            browser = p.webkit.launch()
        else:
            browser = p.chromium.launch(executable_path='/usr/bin/google-chrome' if os.path.exists('/usr/bin/google-chrome') else None,
                                        args=['--disable-features=WebRtcHideLocalIpsWithMdns'])
        print('Browser:', BROWSER, browser.version, flush=True)
        # Unit page runs under the real CSP (no bypass) so CSP violations surface here.
        page = browser.new_page()
        errors = []
        page.on('pageerror', lambda e: errors.append(str(e)))
        page.on('console', lambda m: m.type == 'error' and errors.append(m.text))
        page.goto(url)
        page.wait_for_timeout(500)
        record('page loads without console errors or CSP violations', not errors, '; '.join(errors)[:300])
        for name, ok, detail in page.evaluate(UNIT_JS):
            record('unit ' + name, ok, detail)
        page.close()

        cases = [('small Unicode with CRLF, NUL, emoji (pasted, ~0.3 MB)', 'unicode', 100000),
                 ('small plain text (typed path)', 'log', 50000)]
        if QUICK:
            cases += [('1 MB log', 'log', 1048576)]
        else:
            cases += [
                ('1 MB log', 'log', 1048576),
                ('10 MB log', 'log', 10 * 1048576),
                ('25 MB log', 'log', 25 * 1048576),
                ('50 MB log', 'log', 50 * 1048576),
                ('1,000,000 lines', 'short-lines', 1000000),
                ('2,000,000 lines', 'short-lines', 2000000),
                ('large JSON (~20 MB)', 'json', 20 * 1048576),
                ('large SQL script (~15 MB)', 'sql', 15 * 1048576),
                ('multilingual Unicode (~7 MB)', 'unicode', 10 * 1048576 // 2),
            ]
        for name, kind, size in cases:
            e2e_case(browser, url, name, kind, size)
        fragment_case(browser, url)
        resume_case(browser, url)
        end_session_case(browser, url)
        browser.close()
    srv.shutdown()
    failed = [r for r in RESULTS if not r[1]]
    print('\n%d passed, %d failed' % (len(RESULTS) - len(failed), len(failed)))
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'results-%s.json' % BROWSER), 'w') as f:
        json.dump([{'test': n, 'pass': o, 'detail': d} for n, o, d in RESULTS], f, indent=2, ensure_ascii=False)
    sys.exit(1 if failed else 0)


if __name__ == '__main__':
    main()
