# rawhttp — Architecture

How the code is laid out, how a request flows through it, and the design
decisions behind the parts that aren't obvious.

---

## Layering

```
                       ┌─────────────────────────────────────────┐
   CLI  (main.c)       │ arg parse · mode dispatch · renderers ·  │
                       │ startup banner                           │
                       └───────────────┬─────────────────────────┘
             ┌─────────────┬───────────┼───────────┬──────────────┐
   modes     │ client.c    │ raw.c     │ smuggle.c │ fuzz.c  scan.c│
             │ (normal)    │ (raw/seq) │ (payloads)│ (corpus)(pool)│
             └──────┬──────┴─────┬─────┴─────┬─────┴───────┬───────┘
                    │            │           │             │
   protocol   ┌─────▼────────────▼───────────▼─────────────▼─────┐
              │ request.c  response.c  chunked.c   output.c       │
              │ (build)    (parse)     (decode)    (json/base64)  │
              └───────────────────────┬──────────────────────────┘
                    │  rh_buf (buf.c)  │  rh_url (url.c)
   transport  ┌─────▼──────────────────▼──────────────────────────┐
              │ io.c  (send_all / recv_* / poll idle)              │
              │ transport.c  (rh_transport vtable: TCP | TLS)      │
              │ socket.c  (connect + timeout + CONNECT proxy)      │
              └───────────────────────┬───────────────────────────┘
   base       │ error.c (rh_err + LOG_*)   buf.c (growable bytes)  │
              └───────────────────────────────────────────────────┘
```

Everything below the "modes" row is compiled into `librawhttp.a`; `main.c` is
the only CLI-specific translation unit. That split is what lets the unit tests
and fuzz harnesses link the library directly.

---

## Module reference

| File | Responsibility |
|------|----------------|
| `error.{c,h}` | The single error type `rh_err` returned by every fallible function, `rh_strerror()`, and leveled `LOG_ERR/WARN/INFO/DEBUG` macros gated on one global verbosity. |
| `buf.{c,h}` | `rh_buf`: a growable byte buffer. **Not** NUL-terminated by convention — always `len`, never `strlen` — because HTTP bodies and raw payloads contain `\0`. Growth is overflow-checked. |
| `url.{c,h}` | Hand-rolled `scheme://host[:port][/path]` parser (no regex). http/https only. |
| `socket.{c,h}` | `rh_tcp_connect()` plus process-wide **timeout** and **CONNECT-proxy** config. Non-blocking connect + `poll()` for the connect timeout; `SO_*TIMEO` for I/O. |
| `transport.{c,h}` | `rh_transport`: a read/write/close/get_fd **vtable** with a plain-TCP backend and an OpenSSL TLS backend. Records TTFB (first byte) identically for both. |
| `io.{c,h}` | Transport-level helpers: `rh_send_all` (drains partial writes), `rh_recv_some` (one read), `rh_recv_until_idle` (`poll`-based, for keep-alive raw dumps). |
| `request.{c,h}` | Byte-exact request builder. Adds `Host`/`Connection`/`User-Agent`/`Content-Length` only when absent; otherwise emits caller headers **verbatim, in order**. |
| `response.{c,h}` | Status-line + header-block parser and the Content-Length / until-close body readers. Strict about smuggling-relevant ambiguity. |
| `chunked.{c,h}` | Streaming chunked transfer-encoding decoder with size/line/body limits. |
| `internal.h` | The header-line parser shared **only** between `response.c` and `chunked.c`, so regular headers and chunked trailers parse identically. |
| `client.{c,h}` | `rh_client_request()`: one full protocol-aware round trip. The shared engine behind normal mode **and** the scanner. |
| `raw.{c,h}` | Target parsing, verbatim file loading (+ optional CRLF fixup), and the raw send/dump + same-connection send-sequence with timing. |
| `smuggle.{c,h}` | Technique parsing and the CL.TE / TE.CL / CL.CL payload builders. |
| `fuzz.{c,h}` | The built-in 12-payload corpus and marker substitution. |
| `scan.{c,h}` | A pthread worker pool over a shared work index; per-target results in input order. |
| `output.{c,h}` | `rh_json_escape` and `rh_base64_encode` — pure byte→byte transforms for `--output json`. |
| `main.c` | CLI parsing, mode dispatch, the three response renderers, and the banner. |

---

## Request lifecycle (normal mode)

`rh_client_request()` (`client.c`) is the reference flow:

1. **Parse** the URL → `rh_url` (`url.c`).
2. **Connect** → `rh_tcp_connect()` (`socket.c`), honoring the global
   timeout/proxy config.
3. **Wrap** the fd in a transport → `rh_transport_tcp_init` or
   `rh_transport_tls_init` (`transport.c`). TLS verifies chain **and**
   hostname unless `--insecure`.
4. **Build** the request bytes → `rh_request_build` (`request.c`) into an
   `rh_buf`.
5. **Send** → `rh_send_all` (`io.c`).
6. **Read headers** → `rh_response_read_headers` (`response.c`), which loops
   `rh_recv_some` until it sees `\r\n\r\n`.
7. **Frame the body** by precedence: `Transfer-Encoding: chunked`
   (`chunked.c`) → `Content-Length` → read-until-close.
8. **Timing** (optional) from connect to first byte / to completion.
9. **Render** (`main.c`) and **free** (`rh_response_free`, `rh_buf_free`,
   `transport.close`).

Raw and smuggle modes skip steps 4–8: they write bytes and dump the reply via
`rh_recv_until_idle` (no protocol interpretation — that's the point).

---

## Design decisions

### One error vocabulary
Every fallible function returns `rh_err` — never `-1`/`errno`/`NULL`. Callers
get one consistent failure surface across sockets, TLS, and parsing, and
`rh_strerror` maps it to a message. `RH_ERR_TIMEOUT` and `RH_ERR_LIMIT` carve
out the two "well-formed but refused" cases from generic I/O errors.

### Transport as a vtable
`io.c` and the parsers only ever call `t->read` / `t->write` / `t->get_fd`.
The exact same send/recv loops and parsing work whether the bytes underneath
are a plain socket or a TLS session — the only fork is at init time. Adding a
new backend (say, a mem buffer — which the fuzz harness does) is one struct.

### Bytes, not strings
`rh_buf` tracks `len` and never assumes a trailing NUL. This is load-bearing:
HTTP bodies, chunked data, and smuggling payloads legitimately contain `\0`,
so stdout dumping uses `write()` (not `printf`) and JSON output base64-encodes
the body.

### Ownership contracts
- Transports take ownership of the fd **only on success**; on failure the
  caller still owns and must close it.
- An `rh_response` owns all its strings and its body buffer;
  `rh_response_free` reclaims everything and is safe to call on a zeroed or
  partially-built response (and safe to call twice).
- Parsers self-clean their own partial output on failure.

### Global connection config, set once
`--timeout` and `--proxy` live as file-scope config in `socket.c`, applied
inside `rh_tcp_connect`. Set once from the CLI before any connect, then
read-only — which is exactly what makes them safe to share across the scan
worker threads without a lock, and avoids threading two extra parameters
through every mode's call chain.

### `client.c` factoring
Normal mode and the scanner both call `rh_client_request`, so their
connect/build/frame behavior **cannot drift apart**. Scan workers are just
that function plus a mutex-guarded work index.

### Strictness as a feature
The response parser **rejects** whitespace before a header colon (`Foo : bar`)
instead of tolerating it, because different servers disagree on it and that
disagreement is exploitable. The request builder never "fixes" a caller's
`Content-Length` — duplicate or wrong values are the whole point of desync
testing. A "helpful" library would paper over both; rawhttp exists not to.

### Safety limits
Response parsing is bounded (header block 64 KiB, chunk line 1 KiB, single
chunk 64 MiB, total body 512 MiB) so a hostile or buggy peer fails with
`RH_ERR_LIMIT` rather than driving unbounded allocation. Sending is never
bounded — raw mode writes exactly what you wrote.

### stdout purity
Only the requested payload goes to stdout; the banner, timing, progress, and
logs go to stderr. Output stays pipeable (`| jq`, `> file`) with no stray
bytes, and the banner is additionally gated on `isatty(stderr)`.

---

## Build & test topology

- `make` / `make debug` → `./rawhttp` (release, or ASan+UBSan).
- `librawhttp.a` = every `src/*.c` **except** `main.c`.
- `make test` → one binary per `tests/*.c`, linked against the lib under
  ASan/UBSan, run and aggregated.
- `make fuzz` (clang) / `make fuzz-replay` (gcc) → the libFuzzer targets in
  `tests/fuzz/`, driven through a mem-buffer transport (see
  [fuzz harness](../tests/fuzz/)).
- CI (`.github/workflows/ci.yml`) runs all of the above on every push/PR.

---

## Extending it

- **New transport** (e.g. Unix socket, QUIC): implement the four vtable fns +
  an `_init`; nothing above `transport.c` changes.
- **New smuggling technique**: add a `build_*` in `smuggle.c` and a case in
  `rh_smuggle_build` / `rh_smuggle_parse_technique`.
- **New output format**: add a renderer in `main.c` and a `--output` value.
- **New fuzz target**: drop a `fuzz_*.c` in `tests/fuzz/` exposing
  `LLVMFuzzerTestOneInput`; the Makefile discovers it.
