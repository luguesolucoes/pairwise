# Pairwise

Pairwise moves very large blocks of text (tested to 50 MB and 2,000,000 lines) from one device to another. The sending browser encrypts the text with AES-256-GCM and uploads only the ciphertext to a small server you run. It shows a QR code. The other device opens the link, downloads the ciphertext and decrypts it locally. The decryption key travels only in the link fragment and never reaches the server, so the server only ever holds opaque ciphertext.

Once the QR code is shown, the sending page can be closed. The encrypted text waits on the server until the link is opened or it expires. Everything happens over ordinary HTTPS on port 443, with no WebSockets, no peer-to-peer connection and no third-party services, so it works from networks that only allow plain HTTPS through a proxy.

## Why this shape

An earlier version transferred the text directly between the two browsers over WebRTC. That needs both devices online at once, and the signaling and STUN/TURN traffic uses WebSockets and non-standard ports that many corporate proxies block (the symptom is `Establishing a tunnel via proxy server failed`). This version removes that dependency: the sender uploads once over HTTPS and can then leave. The cost is that the server now stores the ciphertext for the life of the link. It is still zero-knowledge with respect to the key.

## Quick start

```
npm install
node build.mjs                 # writes dist/index.html
node server/server.mjs         # serves the page and the API on http://localhost:8787
```

Open `http://localhost:8787`. `localhost` is a secure context, so Web Crypto works there without TLS. For real use on two separate devices you must serve it over HTTPS (see Deployment); browsers refuse Web Crypto and the clipboard on a plain-HTTP origin that is not localhost.

To send: paste text, choose **Encrypt and upload**, then scan the QR with the other device. To receive: open the link (the camera app does this) or paste it. The text is verified, shown, and offered as **Copy all** or **Save as file** under any name you choose, with any extension or none.

## Architecture

```
Sender browser                              Server (yours)                 Receiver browser
──────────────                              ──────────────                 ────────────────
paste text
  │ single pass: encodeInto → 48 KiB chunks
  │ SHA-256 hash chain → integrity digest
  │ random 16-byte session id + 32-byte key
  │ HKDF-SHA-256 → AES-256-GCM key
  │ seal each chunk; build one blob
  ▼ POST /api/blob (ciphertext only) ───────▶ store under random id, with TTL
  ◀────────────────────────── { id, expiresAt }
  │ build link: https://host/#pw1b!<sid>!<key>!<id>
  ▼ draw QR
QR ─────────── camera ──────────────────────────────────────────────────▶ open link
(sender may now close the page)                                            strip fragment from address bar
                                            GET /api/blob/<id> ◀────────── download ciphertext
                             stream stored ciphertext ──────────────────▶ decrypt each frame,
                             (if "once": delete after a full send)         stream-decode UTF-8,
                                                                           verify hash chain + digest
                                                                           show text; Copy / Save as file
```

The key is in the fragment (after `#`). Browsers never put the fragment in an HTTP request, so the server receives only the random id. The server cannot derive the key or read the text.

Source layout: `src/core.js` (encoding, chunking, crypto, the stored-blob format; pure functions), `src/net.js` (upload and download client), `src/ui.js` (interface), `src/index.template.html` (markup and styles), `build.mjs` (inlines everything into `dist/index.html` with a hash-based CSP), `server/server.mjs` (the backend), `tests/test_pairwise.py` (automated tests).

The spec suggested React, Vite and TypeScript. The page has a handful of states and no component reuse, so a framework would add weight and a build chain without simplifying anything. The front end is plain ES2020 in one inlined file; the only bundled library is the QR generator. The server is plain Node with no dependencies.

## The server

One file, `server/server.mjs`, no dependencies. It streams uploads straight to disk and downloads straight from disk, so a 50 MB blob never sits in server memory. It also serves the built page so the API is same-origin.

Endpoints:

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/blob?ttl=<sec>&once=<0\|1>` | Store a ciphertext blob. Returns `{ id, size, expiresAt, once }`. |
| GET | `/api/blob/<id>` | Stream the ciphertext back. With `once`, the server deletes it after a complete send. |
| GET | `/api/blob/<id>/meta` | `{ id, size, expiresAt, once }`, or 404. |
| DELETE | `/api/blob/<id>` | Delete now. |
| GET | `/api/health` | `{ ok, maxBytes, maxTtl }`; the page uses this to show the size limit. |

Configuration (environment variables):

| Variable | Default | Meaning |
|---|---|---|
| `PAIRWISE_PORT` | 8787 | Listen port. |
| `PAIRWISE_HOST` | 0.0.0.0 | Bind address. |
| `PAIRWISE_STORE` | `./data` | Directory for stored blobs. |
| `PAIRWISE_STATIC` | `../dist/index.html` | The built page to serve. |
| `PAIRWISE_MAX_BYTES` | 67108864 (64 MiB) | Maximum upload size. |
| `PAIRWISE_MAX_TTL` | 86400 (24 h) | Maximum time-to-live. |
| `PAIRWISE_TLS_CERT` / `PAIRWISE_TLS_KEY` | — | If both set, serve HTTPS directly. |
| `PAIRWISE_CORS_ORIGIN` | — | If set, allow this one Origin to call the API cross-site (not needed when the server also serves the page). |
| `PAIRWISE_TRUST_PROXY` | — | `1` to read the client IP from `X-Forwarded-For`. |

Ids are 16 random bytes (32 hex characters) chosen by the server; the client never names a file. Every id is validated against `^[0-9a-f]{32}$` before any filesystem access, so request paths cannot traverse the store. A sweeper runs every minute and deletes expired blobs and stale temp files; blobs are also checked for expiry on every read.

## Deployment

The page needs a secure context, so serve it over HTTPS on a real hostname. Two common ways:

Behind a reverse proxy that terminates TLS (recommended). Run the Node server on localhost and let Caddy or nginx handle the certificate on port 443. With Caddy:

```
pairwise.example.com {
    reverse_proxy 127.0.0.1:8787
}
```

Set `PAIRWISE_TRUST_PROXY=1` so the logs show the real client IP. Reverse proxies also give you rate limiting and request-size limits, which this server keeps minimal on purpose.

Or let Node terminate TLS directly:

```
PAIRWISE_TLS_CERT=/etc/letsencrypt/live/host/fullchain.pem \
PAIRWISE_TLS_KEY=/etc/letsencrypt/live/host/privkey.pem \
PAIRWISE_PORT=443 node server/server.mjs
```

Keep it running with systemd or pm2. A minimal systemd unit:

```
[Service]
WorkingDirectory=/opt/pairwise
ExecStart=/usr/bin/node server/server.mjs
Environment=PAIRWISE_STORE=/var/lib/pairwise PAIRWISE_TRUST_PROXY=1
Restart=on-failure
[Install]
WantedBy=multi-user.target
```

Because all traffic is HTTPS GET and POST on port 443 to one hostname, it passes through the kind of proxy that blocks WebSockets and odd ports.

## Cryptography

- Master key: 32 random bytes from `crypto.getRandomValues`, carried only in the link fragment. The receiver removes the fragment from the address bar and history entry with `history.replaceState` on load.
- HKDF-SHA-256, salted with the 16-byte session id, derives one non-extractable AES-256-GCM key.
- Each 48 KiB chunk is sealed with AES-256-GCM, 128-bit tag. Nonce = frame type (32 bits) ‖ chunk index (64 bits); unique per blob because the key is fresh each time.
- Additional authenticated data = session id ‖ frame type ‖ index ‖ total chunk count. Altered, reordered, truncated or foreign chunks fail to open.
- End-to-end integrity: h₀ = 32 zero bytes, hᵢ = SHA-256(hᵢ₋₁ ‖ chunkᵢ), digest = SHA-256(hₙ ‖ total bytes ‖ count). The digest is in the encrypted manifest; the receiver recomputes it while decrypting and also checks the byte and character counts. Both screens show the first 16 bytes of the digest for a visual compare.
- No custom cryptographic primitives; everything is Web Crypto.

## Stored blob format

`PWB1` magic, then length-prefixed records `[u32 length][frame]`. Record 0 is the encrypted manifest (count, byte and line totals, digest). Records 1..count are the data frames in order. The receiver splits this stream back into frames as it downloads and decrypts them one at a time, so the whole ciphertext is never held in memory at once.

## Large-text handling

- Pastes over 1,000,000 characters, and any paste containing CR, are kept as one JavaScript string and shown in a virtualized viewer that renders only the visible lines. A `<textarea>` is used only for small text, because textareas slow down past a few MB and rewrite CRLF line endings to LF.
- Lines longer than 2,000 characters are shortened on screen only. Uploads, copy and save always carry the complete text; nothing is ever truncated.
- Chunking uses `TextEncoder.encodeInto` into a reused buffer and never splits a code point.
- Unpaired UTF-16 surrogates cannot exist in UTF-8; Pairwise counts them and warns, and each becomes U+FFFD. Everything else round-trips exactly.

## Memory

| | Sender | Server | Receiver |
|---|---|---|---|
| Held | text (1–2× size) + ciphertext blob (~1×, disk-backed by the browser) | nothing in memory; streamed to disk | downloaded text parts, joined at the end (peak ~2×) |
| Rough peak for 50 MB | 150–260 MB | a few MB | 150–200 MB |

Measured JS heap after each size is in the results below. Mobile Safari limits a tab to roughly 1–1.5 GB on recent iPhones, so 50 MB fits; older phones may reload the tab under memory pressure.

## Session lifetime, one-time and deletion

The sender picks a time-to-live (5 minutes to 24 hours) and whether to delete after the first download (on by default). A countdown shows on the sender while the page stays open. The server enforces the TTL regardless, and **Delete now** removes the blob immediately. Keys are non-extractable `CryptoKey` objects; the raw key exists only in the QR code, the link and short-lived variables.

## Threat model

Protected against:

- Network observers, Wi-Fi operators, ISPs: all traffic is HTTPS; inside it, the body is AES-GCM ciphertext.
- The server and its operator: receive only ciphertext and a random id, never the key or the text.
- Tampering, reordering, truncation and foreign data: rejected by GCM authentication with the session id, index and count in the AAD, plus the final digest.
- A guessed id: an attacker who finds a blob id still cannot decrypt without the key, which is never sent to the server.

Not protected against:

- Anyone who sees or photographs the QR code or the link. It contains the key. Treat it like a password; use a short TTL and "delete after first download".
- A compromised browser, extension or OS on either device. They can read the text before encryption or after decryption.
- A malicious or compromised copy of the page. Whoever serves `index.html` controls the code that handles the key, so host it yourself and keep the server trusted. Pinning a known hash of `index.html` is the practical check.
- Traffic analysis. The server and on-path observers learn both devices' IP addresses, the ciphertext size and the timing. The ciphertext is about the plaintext size.
- A server operator who logs or copies the ciphertext. They still cannot read it, but they can keep the opaque blob beyond its TTL. Run a server you trust.
- Denial of service. This server has only basic limits (size cap, TTL, id validation). Put it behind a reverse proxy for rate limiting and abuse controls.

## Browser compatibility

| Browser | Status |
|---|---|
| Chrome / Edge (desktop, Android) | Tested automatically (Chrome 153, headless). Full feature set, including the native save dialog. |
| Safari (macOS, iOS 15+) | Not tested here (the environment could not download WebKit). Uses only standard APIs Safari supports: Web Crypto AES-GCM/HKDF, `fetch` with streaming responses, `TextEncoder.encodeInto`. Saving falls back to a download. Test with `tests/test_pairwise.py` on a machine with WebKit before relying on it. |
| Firefox | Not tested. Expected to work; `navigator.clipboard.readText` is unavailable, so use Ctrl+V. |

Real phone-to-laptop use (scanning the QR on a phone) was not tested in this environment; there is no camera or second device here.

## Testing

```
pip install playwright
python3 tests/test_pairwise.py           # full suite; starts the Node server itself
python3 tests/test_pairwise.py --quick    # unit tests + small transfers
```

The suite runs the built page, served by the real Node backend, in headless Chrome across two isolated browser contexts. Unit tests cover base64url, UTF-8 length, line counting, chunking at several byte boundaries with emoji and combining characters, the hash chain, AES-GCM round trips, rejection of tampered/reordered/truncated/cross-session frames, the stored-blob splitter including bad magic and truncation, manifest validation and link parsing including path-traversal attempts. End-to-end tests upload through the real UI and download in a second context, comparing SHA-256 of the original and reconstructed text. One case closes the sender's page before the receiver opens the link, to prove the transfer no longer depends on the sender staying online. Others cover one-time deletion, multi-open links, delete-now, the size cap (413), and that the server's request log never contains key material.

### Results (Chrome 153 headless, Linux, 2026-11-02)

14 of 14 unit tests passed. End-to-end cases upload through the real UI to the Node server, then download and decrypt in a separate browser context; every row compares SHA-256 of the original and the reconstructed text.

| Case | Characters | Lines | UTF-8 | Upload+encrypt | Download+decrypt | JS heap S / R | Result |
|---|---|---|---|---|---|---|---|
| sender closed before receiver opens (10 MB) | 10,485,799 | 117,364 | 10.0 MiB | 0.5 s | 0.3 s | 44 / 33 MiB | pass |
| small plain text | 50,075 | 588 | 0.0 MiB | 0.2 s | 0.3 s | 3 / 3 MiB | pass |
| Unicode with CRLF/NUL/emoji | 200,005 | 9,171 | 0.3 MiB | 0.2 s | 0.2 s | 5 / 5 MiB | pass |
| 1 MB log | 1,048,599 | 11,972 | 1.0 MiB | 0.2 s | 0.2 s | 13 / 11 MiB | pass |
| 10 MB log | 10,485,799 | 117,364 | 10.0 MiB | 0.7 s | 0.7 s | 44 / 33 MiB | pass |
| 25 MB log | 26,214,425 | 290,420 | 25.0 MiB | 1.5 s | 0.7 s | 236 / 78 MiB | pass |
| 50 MB log | 52,428,832 | 578,847 | 50.0 MiB | 1.8 s | 1.2 s | 256 / 154 MiB | pass |
| 1,000,000 lines | 16,777,822 | 1,000,000 | 16.0 MiB | 0.8 s | 0.4 s | 187 / 54 MiB | pass |
| 2,000,000 lines | 34,666,754 | 2,000,000 | 33.1 MiB | 1.4 s | 0.5 s | 176 / 109 MiB | pass |
| large JSON (~20 MB) | 20,971,559 | 1,548,918 | 20.3 MiB | 0.9 s | 0.4 s | 233 / 88 MiB | pass |
| large SQL (~15 MB) | 15,728,659 | 151,915 | 15.0 MiB | 0.6 s | 0.3 s | 79 / 48 MiB | pass |
| multilingual Unicode (~7 MB) | 3,670,015 | 158,017 | 5.0 MiB | 0.3 s | 0.2 s | 39 / 42 MiB | pass |

- page loads without console errors or CSP violations: pass ()
- once=1 deletes after first download: pass (first matched=True, second as expected=True)
- once=0 allows a second open: pass (first matched=True, second as expected=True)
- delete now removes the blob from the server: pass (receiver saw: This transfer no longer exists. It may have expired or already been opened.)
- server request log never contains key material: pass (115 API requests logged; sample paths: /, /api/blob, /api/blob/0ce51d960e882f273de5ab7cb6f7bc64, /api/blob/0ce51d960e882f273de5ab7cb6f7bc64/meta, /api)
- server rejects oversize upload (413) but accepts small: pass (oversize status=413, small id=True)

Times are loopback on one machine; real transfers are bounded by the network between each device and the server. The retrieval link (and the QR) was 128 characters in every case, independent of payload size, because only the id and key travel in it.


## Known limitations

- You run the server, and it holds the ciphertext until the link is opened or expires. This is the deliberate trade for letting the sender close the page; it is not the "nothing leaves the browser" model of a peer-to-peer transfer.
- Needs a secure context, so HTTPS on a real hostname for two-device use. `localhost` works for a single machine.
- Safari, Firefox and real phone-to-laptop scanning are untested here.
- Resuming a half-finished download is not implemented; a dropped download is retried by opening the link again (works while the blob still exists, so pair a longer TTL with multi-open if you expect flaky connections).
- Unpaired UTF-16 surrogates become U+FFFD (with a warning).
- Large text is read-only in the editor; editing is limited to small texts.
- Copying 50 MB to the clipboard can be slow and some browsers refuse very large clipboard writes; Save as file always works.
