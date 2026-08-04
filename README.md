# rawhttp

A low-level, memory-safe raw-socket HTTP client written in C, built for
HTTP request smuggling / desync research. No libcurl, no normalization —
`rawhttp` writes exactly the bytes you give it, which is what makes CL.TE,
TE.CL, and CL.TE desync payloads possible in the first place.

Status: **Phase 2 (real client) complete.** Pentest weapon (Phase 3) next.

```
$ ./rawhttp -X POST -H 'Content-Type: application/json' -d '{"x":1}' https://example.com/api
HTTP/1.1 200 OK
Content-Type: application/json
...
```

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
