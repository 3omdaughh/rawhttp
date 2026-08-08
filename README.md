# rawhttp

A low-level, memory-safe raw-socket HTTP client written in C, built for
HTTP request smuggling / desync research. No libcurl, no normalization —
`rawhttp` writes exactly the bytes you give it, which is what makes CL.TE,
TE.CL, and CL.TE desync payloads possible in the first place.

Status: **Phase 3 (pentest weapon) complete.** Polish (Phase 4) next.

```
$ ./rawhttp --smuggle cl.te --target vulnerable-website.com:80 --probe
--- cl.te payload, sending 97 bytes to vulnerable-website.com:80 ---
00000000  50 4f 53 54 20 2f 20 48  54 54 50 2f 31 2e 31 0d  |POST / HTTP/1.1.|
...
--- then a probe request, same connection ---
...
--- received N bytes ---
HTTP/1.1 200 OK
...
```

## Modes

- **Normal**: `./rawhttp [-X METHOD] [-H 'K: V'] [-d DATA] URL` — a real HTTP/1.1
  client (chunked/Content-Length aware, TLS with verification on by default).
- **Raw** (`--raw FILE --target host:port`): sends FILE's bytes verbatim,
  zero normalization. `--raw2` sends a second payload on the same connection.
- **Smuggle** (`--smuggle cl.te|te.cl|cl.cl --target host:port`): generates
  and sends a CL.TE/TE.CL/CL.CL payload. `--probe` fires a follow-up request
  on the same connection to confirm a desync actually happened.
- **Fuzz** (`--fuzz FILE --target host:port`): replays a mutation corpus
  against a template (marker-based), diffs every result against a baseline,
  flags anomalies.

Run `./rawhttp --help` for the full flag list, or see `examples/` for
ready-to-use payload templates.

## Build

Requires OpenSSL development headers (`libssl-dev` on Debian/Ubuntu;
already present via the base `openssl` package on Arch).

```sh
make            # release build -> ./rawhttp
make debug      # ASan + UBSan build
make test       # run test suite (wired up in Phase 5)
make clean
```

## Legal

Only point this at hosts you own or are explicitly authorized to test
(e.g. your own lab, PortSwigger Web Security Academy). Sending smuggling
payloads at systems without authorization is illegal.
