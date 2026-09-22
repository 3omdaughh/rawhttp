# rawhttp

A low-level, memory-safe raw-socket HTTP client written in C, built for HTTP
request smuggling / desync research. No libcurl, no normalization — `rawhttp`
writes exactly the bytes you give it, which is what makes CL.TE, TE.CL, and
CL.CL desync payloads possible in the first place.

**Status: Phase 5 complete.** Real client, TLS (verify-on), the pentest
weapon (raw / smuggle / fuzz), Phase 4 polish (timeouts, proxy, concurrent
scan, output formats), and Phase 5 (wired `make test`, CI, libFuzzer harnesses,
docs).

```
$ ./rawhttp --smuggle cl.te --target victim.lab:80 --probe
--- cl.te payload, sending 97 bytes to victim.lab:80 ---
00000000  50 4f 53 54 20 2f 20 48  54 54 50 2f 31 2e 31 0d  |POST / HTTP/1.1.|
...
--- then a probe request, same connection ---
--- received N bytes ---
HTTP/1.1 200 OK
...
```

## Documentation

- **[docs/USAGE.md](docs/USAGE.md)** — full, example-driven guide to every
  mode and flag. Start here.
- **[docs/SMUGGLING.md](docs/SMUGGLING.md)** — CL.TE / TE.CL / CL.CL theory,
  payload anatomy, and how to confirm a desync.
- **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** — module map, request
  lifecycle, and the design decisions behind the non-obvious parts.

## Modes

- **Normal** — `rawhttp [-X METHOD] [-H 'K: V'] [-d DATA] URL`: a real
  HTTP/1.1 client (chunked/Content-Length aware, TLS with verification on).
- **Raw** — `--raw FILE --target host:port`: sends FILE's bytes verbatim,
  zero normalization. `--raw2` sends a second payload on the same connection.
- **Smuggle** — `--smuggle cl.te|te.cl|cl.cl --target host:port`: generates
  and sends a desync payload. `--probe` fires a follow-up on the same
  connection to confirm a desync happened.
- **Fuzz** — `--fuzz FILE --target host:port`: replays a mutation corpus
  against a marker-based template, diffs each result against a baseline.
- **Scan** — `--scan-file FILE --concurrency N`: fetches many URLs in
  parallel (pthreads), one result line each.

Global flags (all modes): `--timeout MS`, `--proxy host:port`,
`--output raw|pretty|json`, `--insecure`, `--timing`. Run `./rawhttp --help`
for everything, or see [`examples/`](examples/) for ready-to-use payloads.

## Build

Requires a C11 compiler and OpenSSL development headers (`libssl-dev` on
Debian/Ubuntu; already present via the base `openssl` package on Arch).

```sh
make            # release build -> ./rawhttp
make debug      # ASan + UBSan build
make test       # build + run the unit suite (ASan/UBSan)
make clean
```

Fuzzing (optional):

```sh
make fuzz          # libFuzzer targets -> build/fuzz/ (needs clang)
make fuzz-replay   # gcc + ASan: replay the seed corpus once (no clang)
```

CI (`.github/workflows/ci.yml`) runs the release build, unit tests, corpus
replay, and a short libFuzzer smoke run on every push and pull request.

## Legal

Only point this at hosts you own or are explicitly authorized to test (e.g.
your own lab, the PortSwigger Web Security Academy). Sending smuggling or
fuzzing payloads at systems without authorization is illegal.

## License

MIT — see [LICENSE](LICENSE).
