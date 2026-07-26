# rawhttp

A low-level, memory-safe raw-socket HTTP client written in C, built for
HTTP request smuggling / desync research. No libcurl, no normalization —
`rawhttp` writes exactly the bytes you give it, which is what makes CL.TE,
TE.CL, and CL.TE desync payloads possible in the first place.

Status: **Phase 0 (project setup) complete.** Walking skeleton (Phase 1) next.

## Build

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
