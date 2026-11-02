# Pairwise

Pairwise moves very large blocks of text (tested to 50 MB and 2,000,000 lines) from one browser to another. The text is encrypted in the sending browser with AES-256-GCM and sent directly to the receiving browser over a WebRTC data channel. Devices pair by scanning QR codes. There is no backend: the whole application is one static `index.html` (about 240 KB, no runtime dependencies, no external requests).

## Quick start

```
npm install          # build tooling and the two QR libraries that get inlined
node build.mjs       # writes dist/index.html and a copy at ./index.html
```

The committed `index.html` at the repository root is the built app; GitHub Pages serves it directly. Serve it from any static host over HTTPS (GitHub Pages, Cloudflare Pages, Netlify, S3, nginx). WebRTC, the Web Crypto API and camera access all require a secure context, so plain HTTP only works on `localhost`.

To send: paste text, choose **Encrypt and pair**, scan the QR with the other device, then scan the answer QR the other device shows (or paste its answer code). The receiver verifies everything and shows the text with Copy and Download buttons.

## Architecture

```
Sender browser                                                   Receiver browser
──────────────                                                   ────────────────
text (JS string, never copied into a textarea when large)
  │ single pass: TextEncoder.encodeInto → 48 KiB chunks
  │ SHA-256 hash chain → integrity digest
  │ random 16-byte session id + 32-byte master key
  │ HKDF-SHA-256 → AES-256-GCM key + HMAC key
  │ RTCPeerConnection.createOffer → compact offer
  ▼
QR 1: https://host/#pw1!<sid>!<key>!<compact offer>  ── camera ──▶  opens page, strips fragment from
                                                                    address bar, derives the same keys,
                                                                    createAnswer → compact answer
QR 2:                       pwa1!<sid>!<compact answer> ◀── camera ──
  │ setRemoteDescription
  ▼
  ═════════════ WebRTC data channel (DTLS, direct or via optional TURN) ═════════════
  ◀── challenge: random nonce
  ──▶ HMAC(auth key, nonce), "I already have N chunks"
  ◀── manifest frame (encrypted): count, bytes, chars, lines, digest, expiry
  ◀── data frames i = N … count-1, each AES-GCM sealed, sent with backpressure
  ──▶ ack every 16 chunks
                                                                    decrypt each frame, stream-decode UTF-8,
                                                                    extend hash chain, compare final digest
  ──▶ done(ok, digest)  → both sides show "verified", connection closes, keys dropped
```

Source layout: `src/core.js` (encoding, chunking, crypto, framing, compact signaling; pure functions), `src/session.js` (WebRTC and the transfer protocol), `src/ui.js` (interface), `src/index.template.html` (markup and styles), `build.mjs` (inlines everything into `dist/index.html` and writes a hash-based Content Security Policy), `tests/test_pairwise.py` (automated tests).

The spec suggested React, Vite and TypeScript. The interface has about ten states and no component reuse, so React would add ~45 KB and a build chain without removing any code that matters, and a single inlined file is the simplest thing to audit and deploy. The code is plain ES2020 with no framework; the build step only minifies the two QR libraries and inlines files.

## QR-based pairing (no signaling server)

A data-channel-only WebRTC session needs very little from the SDP: ICE username fragment and password, the DTLS certificate fingerprint, the DTLS role, the max message size and the network candidates. Pairwise extracts just those fields, waits for candidate gathering to finish (non-trickle), and rebuilds a standard SDP from a fixed template on the other side. Measured sizes:

| Payload | Size | QR |
|---|---|---|
| Offer link (host candidate only, URL included) | ~205 characters | version 10, 57×57 modules |
| Answer code | ~128 characters | version 7 |
| Offer with STUN (host + server-reflexive candidates) | ~260–330 characters | version 11–13 |

All of these scan easily from a laptop screen with a phone camera. Full SDP (about 600–1,500 bytes) would also fit in a QR code, but at a density that phone cameras read poorly from screens; the compact form avoids that.

The answer has to travel back to the sender. The sender page can read it with the laptop's webcam, or the user can copy the answer code and paste it on the sender. The answer contains no key material.

**Feasibility verdict:** implemented. The cost is a second scan in the reverse direction, which needs a camera on the sending device or a way to move a ~130-character code.

## Cryptography

- Master key: 32 random bytes from `crypto.getRandomValues`, carried only in the URL fragment of QR 1. Fragments are not sent in HTTP requests; the test suite checks the server log to confirm this. The receiver removes the fragment from the address bar and history entry with `history.replaceState` immediately on load.
- HKDF-SHA-256 with the 16-byte session id as salt derives two non-extractable keys: AES-256-GCM (`info = "pw1/enc"`) and HMAC-SHA-256 (`info = "pw1/auth"`).
- Each chunk is sealed with AES-256-GCM, 128-bit tag. Nonce = frame type (32 bits) ‖ chunk index (64 bits). The key is unique to the session and every (type, index) pair encrypts exactly one fixed plaintext, so nonces never repeat with different data, including on resume.
- Additional authenticated data = session id ‖ frame type ‖ index ‖ total chunk count. This rejects altered, reordered, truncated or cross-session replayed frames.
- End-to-end integrity: h₀ = 32 zero bytes, hᵢ = SHA-256(hᵢ₋₁ ‖ chunkᵢ), digest = SHA-256(hₙ ‖ total bytes ‖ count). The digest travels in the encrypted manifest; the receiver recomputes it while decrypting and also checks byte and character counts. Both screens show the first 16 bytes of the digest so a person can compare them.
- Before any data is sent, the receiver must answer an HMAC challenge, which proves it holds the key.
- No custom cryptographic primitives are used; everything is Web Crypto.

## Networking

What crosses the network, completely:

| Traffic | When | Who sees what |
|---|---|---|
| `GET index.html` | page load | the static host sees an ordinary page request, never the fragment |
| STUN binding request to `stun.l.google.com:19302` | if "Use the public STUN server" is on (default) | Google learns each device's public IP address and that it is using WebRTC |
| WebRTC ICE, DTLS, SCTP | during the transfer | the two devices see each other's IP addresses; on-path observers see encrypted UDP traffic of a given size and timing |
| TURN relay | only if you configure one | the relay sees both IP addresses and the traffic volume, not the content |

The page's Content Security Policy is `default-src 'none'; connect-src 'none'` with hash-pinned scripts, so the page cannot make `fetch`, XHR, WebSocket or beacon requests at all. The test suite confirms the CSP blocks a POST. There is no upload endpoint to misuse.

Connectivity: two devices on the same Wi-Fi connect without STUN. Devices on different networks (phone on mobile data, laptop on Wi-Fi) usually need STUN. Symmetric NATs and many corporate or guest networks block direct UDP; those need a TURN server, which you must supply (Pairwise does not ship credentials for one). Pairwise does not try to get around firewalls or network policy: if the network does not allow a direct or TURN-relayed WebRTC connection, the transfer fails with a clear message.

## Large-text handling

- Pastes over 1,000,000 characters, and any paste containing CR characters, are intercepted from the `paste` event and kept as one JavaScript string. They are shown in a virtualized viewer that renders only the visible lines (with proportional scrolling so 2,000,000-line documents stay under browser element-height limits). A `<textarea>` is used only for small text, because textareas both slow down badly past a few MB and convert CRLF line endings to LF.
- Lines longer than 2,000 characters are shortened on screen only, with a visible marker. Transfers, copy and download always carry the complete text. Nothing is ever truncated.
- Chunking uses `TextEncoder.encodeInto` into a reused 48 KiB buffer and never splits a code point. Chunks are encrypted just before they are sent, so the encrypted payload is never held in memory as a whole: at most ~4 MiB is in the data channel's buffer at a time (pause above 4 MiB, resume below 1 MiB).
- The receiver decrypts and UTF-8 decodes each chunk as it arrives and keeps no ciphertext.
- Text containing unpaired UTF-16 surrogates (malformed Unicode, rare in clipboard text) cannot be represented in UTF-8. Pairwise counts them and warns before sending; each becomes U+FFFD. All other characters, whitespace and line endings round-trip exactly.

## Memory requirements (estimated and measured)

V8 stores Latin-1-only strings at 1 byte per character and other strings at 2 bytes per character.

| | Sender | Receiver |
|---|---|---|
| Text held | 1–2 × text size | 1–2 × text size |
| Transient | clipboard copy during paste (1×), line index (4 bytes per line), ≤ 4 MiB in flight | string parts + joined string at completion (peak 2×), line index |
| Download | — | Blob UTF-8 copy at click (1×) |
| Rough peak for 50 MB | 150–250 MB | 150–250 MB |

Measured JS heap after the 50 MB test in Chrome is in the test results below. Mobile Safari limits a tab to roughly 1–1.5 GB on recent iPhones, so 50 MB fits, but older phones with 2–3 GB of RAM may reload the tab under memory pressure.

## Session lifetime and destruction

The sender picks a lifetime (5, 15, 30 or 60 minutes; default 15). A countdown shows on both devices. At expiry, or when either side chooses **End session**, the connection closes and references to the key material are dropped. After a verified transfer the receiver closes the connection automatically and keeps only the decrypted text, which **Clear** removes from the page. Keys are non-extractable `CryptoKey` objects; the raw key bytes exist only in the QR code, the link and short-lived variables.

If the connection drops mid-transfer, the sender creates a new pairing code for the same session. The receiver scans it and reports how many chunks it already verified; sending resumes from there. Resume works only while both pages stay open: nothing is persisted to disk.

## Threat model

**Protected against**

- Static host or CDN serving the page: never receives the key or the content (the key is in the fragment; the CSP forbids outbound requests). It could serve a malicious page instead, see below.
- Network observers, Wi-Fi operators, ISPs, STUN and TURN servers: see encrypted DTLS traffic; inside it, each chunk is AES-GCM sealed with a key they never see.
- Tampering, reordering, truncation and replay of chunks or of a whole session: rejected by GCM authentication with the session id, index and count bound in the AAD, plus the final digest.
- A third device that obtains only the answer code, or connects with a guessed answer: cannot pass the HMAC challenge, so the sender sends nothing.
- Signaling infrastructure: there is none. Pairing data moves only through QR codes or text you copy.

**Not protected against**

- Anyone who sees or photographs the first QR code or link while the session is live. It contains the key. Treat it like a password: don't screen-share it, and end the session when done.
- A compromised browser, extension or operating system on either device. They can read the text before encryption or after decryption.
- A malicious or compromised copy of the page. Whoever serves `index.html` controls the code that handles the key. Host it yourself, or compare the file against the source. Subresource Integrity does not help here because the code is inline; pinning a known hash of `index.html` is the practical check.
- Malicious recipient URLs. Someone could show a QR pointing to a look-alike page. Pairwise always builds the link from its own address; check the host name when the camera app shows the link.
- Session hijacking by someone who has QR 1: they could connect first. The legitimate receiver would then fail to connect and both screens would show the mismatch; the sender's log shows which device connected. Shorter lifetimes reduce the window.
- Memory exposure. JavaScript cannot reliably zero strings; decrypted text lives in the page's memory until the tab closes and may be paged to disk by the OS.
- Metadata. The two devices learn each other's IP addresses; STUN reveals your public IP to the STUN server; traffic size reveals approximately how much text was sent.
- Clipboard managers. Copying the received text puts it wherever your clipboard goes.

## Browser compatibility

| Browser | Status |
|---|---|
| Chrome / Edge (desktop, Android) | Tested automatically (Chrome 153, headless). Full feature set including native `BarcodeDetector` scanning. |
| Safari (macOS, iOS 15+) | **Not tested.** The test environment could not download WebKit. Uses only standard APIs that Safari supports (WebRTC data channels, Web Crypto AES-GCM/HKDF, `TextEncoder.encodeInto`); QR scanning falls back to the bundled jsQR decoder. Run `python3 tests/test_pairwise.py --browser webkit` locally before relying on it. |
| Firefox | Not tested. Expected to work; `navigator.clipboard.readText` is unavailable, so use Ctrl+V. |

Cross-device pairing between a real phone and a laptop was not tested in this environment (no camera, no second physical device).

## Testing

```
pip install playwright        # Python test runner
python3 tests/test_pairwise.py           # full suite (~5–10 minutes)
python3 tests/test_pairwise.py --quick   # unit tests + small transfers
python3 tests/test_pairwise.py --browser webkit
```

The suite runs the built page in a real browser. Unit tests cover base64url, UTF-8 length, line counting, chunking at every byte boundary with emoji and combining characters, the hash chain, AES-GCM round trips, rejection of tampered/reordered/truncated/cross-session frames, nonce uniqueness, the HMAC challenge, manifest validation, compact SDP producing a working data channel, and code parsing including SDP-injection attempts. End-to-end tests drive the real UI in two isolated browser contexts over real WebRTC and compare SHA-256 of the original and reconstructed text. Results are written to `tests/results-<browser>.json`.

### Results (Chrome 153 headless, Linux, 2026-11-02)

24 of 24 unit tests passed. End-to-end transfers between two isolated browser contexts; every row compares SHA-256 of the original and the reconstructed text:

| Case | Characters | Lines | UTF-8 | Transfer + verify | JS heap sender / receiver | Result |
|---|---|---|---|---|---|---|
| small Unicode with CRLF, NUL, emoji (pasted, ~0.3 MB) | 100,016 | 3,596 | 0.1 MiB | 0.1 s | 6 / 5 MiB | pass |
| small plain text (typed path) | 50,054 | 581 | 0.0 MiB | 0.0 s | 5 / 4 MiB | pass |
| 1 MB log | 1,048,601 | 11,839 | 1.0 MiB | 0.1 s | 14 / 10 MiB | pass |
| 10 MB log | 10,485,807 | 116,086 | 10.0 MiB | 4.3 s | 55 / 33 MiB | pass |
| 25 MB log | 26,214,442 | 287,259 | 25.0 MiB | 2.9 s | 235 / 95 MiB | pass |
| 50 MB log | 52,428,814 | 572,547 | 50.0 MiB | 3.8 s | 207 / 208 MiB | pass |
| 1,000,000 lines | 16,777,822 | 1,000,000 | 16.0 MiB | 2.8 s | 187 / 72 MiB | pass |
| 2,000,000 lines | 34,666,754 | 2,000,000 | 33.1 MiB | 3.8 s | 144 / 121 MiB | pass |
| large JSON (~20 MB) | 20,971,521 | 1,547,040 | 20.3 MiB | 1.4 s | 234 / 89 MiB | pass |
| large SQL script (~15 MB) | 15,728,692 | 133,176 | 15.0 MiB | 2.8 s | 81 / 63 MiB | pass |
| multilingual Unicode (~7 MB) | 5,242,882 | 177,726 | 7.4 MiB | 2.8 s | 26 / 50 MiB | pass |

- page loads without console errors or CSP violations: pass ()
- QR link flow: key never reaches the server, removed from address bar: pass (server saw key=False, address bar clean=True, server request lines: ['GET /index.html?test=1 HTTP/1.1'])
- resume after dropped connection: pass (dropped at chunk 151; sender log shows resume=True)
- manual session end discards session: pass (UI cleared=True, editor unlocked=True, stale code opened no channel=True)

Times are loopback on one machine; real transfers are bounded by the network between the devices. Offer link was 205 characters and the answer 128 characters in every run (host candidates only, no STUN in the test environment).

## Known limitations

- Safari, Firefox and real phone-to-laptop pairing are untested (see above).
- Different networks often need STUN; restrictive networks need a TURN server you provide.
- The sender needs a camera to scan the answer, or the user must move a ~130-character answer code to it.
- Resume requires both pages to stay open; reloading either page loses the session.
- Unpaired UTF-16 surrogates become U+FFFD (with a warning).
- Large text is read-only in the editor; editing is limited to small texts.
- Copying 50 MB to the clipboard can take several seconds and some browsers refuse very large clipboard writes; Download always works.
- Not usable inside sandboxed iframes that block WebRTC or camera access (for example, some preview environments). Host the file directly.
