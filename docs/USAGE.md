# rawhttp — Usage Guide

A complete, example-driven reference for every mode and flag.

> **Authorization.** Only send requests — especially smuggling/fuzzing
> payloads — at hosts you own or are explicitly authorized to test (your own
> lab, the [PortSwigger Web Security Academy](https://portswigger.net/web-security)).
> Unauthorized use is illegal.

---

## Contents

- [Install & build](#install--build)
- [The five modes at a glance](#the-five-modes-at-a-glance)
- [Global options](#global-options-all-modes)
- [1. Normal client mode](#1-normal-client-mode)
- [2. Raw mode](#2-raw-mode)
- [3. Smuggle mode](#3-smuggle-mode)
- [4. Fuzz mode](#4-fuzz-mode)
- [5. Scan mode](#5-scan-mode)
- [Output formats](#output-formats)
- [Timeouts](#timeouts)
- [Proxying (Burp / upstream)](#proxying-burp--upstream)
- [Exit codes & stdout/stderr contract](#exit-codes--stdoutstderr-contract)
- [Safety limits](#safety-limits)

---

## Install & build

Requires a C11 compiler and OpenSSL headers.

```sh
# Debian/Ubuntu: sudo apt-get install libssl-dev
# Arch:          already present via the base `openssl` package
make            # release build -> ./rawhttp
make debug      # same, with AddressSanitizer + UBSan
make test       # build + run the unit suite (ASan/UBSan)
make clean
```

Fuzzing (optional, needs clang for libFuzzer):

```sh
make fuzz          # build libFuzzer targets -> build/fuzz/
make fuzz-replay   # gcc + ASan: replay the seed corpus once (no clang needed)
```

---

## The five modes at a glance

| Mode | Trigger | What it does |
|------|---------|--------------|
| **Normal** | a `URL` argument | Real HTTP/1.1 client: builds the request, frames the response (chunked / Content-Length / until-close), TLS with verification on. |
| **Raw** | `--raw FILE --target H:P` | Sends `FILE`'s bytes **verbatim**, zero normalization. Dumps whatever comes back. |
| **Smuggle** | `--smuggle TECH --target H:P` | Generates and sends a CL.TE / TE.CL / CL.CL desync payload. |
| **Fuzz** | `--fuzz FILE --target H:P` | Replays a mutation corpus against a template, diffs each result vs a baseline. |
| **Scan** | `--scan-file FILE` | Fetches many URLs concurrently (pthreads), one result line each. |

The modes are mutually exclusive. Every mode honors the [global options](#global-options-all-modes) below.

---

## Global options (all modes)

| Flag | Meaning |
|------|---------|
| `--timeout MS` | Connect **and** per read/write timeout in milliseconds. `0` (default) = no timeout. See [Timeouts](#timeouts). |
| `--proxy host:port` | Tunnel every connection through an HTTP `CONNECT` proxy. See [Proxying](#proxying-burp--upstream). |
| `--output raw\|pretty\|json` | Response rendering for **normal** and **scan** modes. Default `raw`. See [Output formats](#output-formats). |
| `--insecure` | Skip TLS certificate verification (chain **and** hostname). Opt-in, for lab targets with self-signed certs. |
| `--timing` | Print TTFB / total timing to stderr. |
| `-h`, `--help` | Full flag list. |

A slanted ASCII banner prints to **stderr** on startup when stderr is a
terminal (suppressed when redirected/piped; honors `NO_COLOR`). It never
touches stdout.

---

## 1. Normal client mode

```
rawhttp [-X METHOD] [-H 'K: V'] [-d DATA | --data-file FILE] [options] URL
```

A standards-aware HTTP/1.1 client. Parses the URL, connects (TLS for
`https://`), builds the request, and frames the response body using the same
precedence a real client does: **chunked → Content-Length → read-until-close**.

### Options

| Flag | Meaning |
|------|---------|
| `-X, --method METHOD` | HTTP method. Default `GET`, or `POST` when a body is given. |
| `-H 'Name: Value'` | Add a request header. Repeatable. Sent **verbatim, in order**. |
| `-d, --data DATA` | Request body from a literal string. |
| `--data-file FILE` | Request body read verbatim from a file (binary-safe). |

### Auto-added headers

Unless you supply your own (case-insensitive match), rawhttp adds:

- `Host:` — from the URL authority (with a non-default port when relevant).
- `Connection: close`
- `User-Agent: rawhttp/0.1`
- `Content-Length:` — only when there is a body.

Supplying any of these via `-H` suppresses the auto version — that is the
control surface the smuggling/desync work relies on.

### Examples

```sh
# Simplest GET
rawhttp http://example.com/

# HTTPS with timing
rawhttp --timing https://example.com/

# Custom method + headers + JSON body
rawhttp -X POST \
        -H 'Content-Type: application/json' \
        -H 'Authorization: Bearer TOKEN' \
        -d '{"hello":"world"}' \
        https://api.example.com/v1/things

# Body from a file, machine-readable output
rawhttp --data-file ./payload.bin --output json https://example.com/upload

# Talk to a self-signed lab host
rawhttp --insecure https://localhost:8443/
```

---

## 2. Raw mode

```
rawhttp --raw FILE --target host:port [--raw2 FILE] [--crlf] [--tls] [options]
```

Sends the exact bytes of `FILE` on the wire — **no** request building, **no**
header normalization, **no** response parsing. It connects, writes the bytes,
then reads until the peer closes or goes idle (`RH_RAW_IDLE_TIMEOUT_MS`, 2s),
and dumps everything received. This is what makes hand-crafted, deliberately
malformed requests possible.

| Flag | Meaning |
|------|---------|
| `--raw FILE` | The payload file. |
| `--raw2 FILE` | Optional second payload, sent **immediately after** the first on the **same connection** (real pipelining). |
| `--target host:port` | Where to connect (required — raw mode has no URL/scheme). |
| `--crlf` | Convert every lone `\n` (not already `\r\n`) to `\r\n` before sending, so you can author payloads in a normal editor. Existing `\r\n` is left untouched. |
| `--tls` | Wrap the connection in TLS. |

rawhttp prints a hex+ASCII dump of exactly what it sends before sending, so
you can trust the bytes.

### Example

```sh
printf 'GET / HTTP/1.1\r\nHost: victim\r\nConnection: close\r\n\r\n' > req.txt
rawhttp --raw req.txt --target victim.lab:80
```

---

## 3. Smuggle mode

```
rawhttp --smuggle cl.te|te.cl|cl.cl --target host:port [options]
```

Generates a request-smuggling payload and sends it like raw mode. See
[SMUGGLING.md](SMUGGLING.md) for the theory and payload anatomy.

| Flag | Meaning | Default |
|------|---------|---------|
| `--smuggle TECH` | `cl.te`, `te.cl`, or `cl.cl` (case-insensitive). | — |
| `--target host:port` | Where to connect. | — |
| `--path PATH` | Request path. | `/` |
| `--smuggle-host H` | `Host` header value. | the `--target` host |
| `--smuggled BYTES` | The bytes left dangling for the desynced back-end. | `SMUGGLED` |
| `--cl1 N` | Override the first `Content-Length`. | technique default |
| `--cl2 N` | Override CL.CL's second `Content-Length`. | technique default |
| `--probe` | After the payload, send a plain follow-up `GET /rawhttp-probe` on the **same connection**. A wrong-looking response to the probe is what actually confirms a desync. | off |

### Examples

```sh
# Generate + send a CL.TE payload, then confirm with a probe
rawhttp --smuggle cl.te --target victim.lab:80 --probe --timing

# TE.CL against a specific vhost/path
rawhttp --smuggle te.cl --target victim.lab:80 \
        --smuggle-host app.internal --path /admin

# CL.CL with a deliberate header disagreement
rawhttp --smuggle cl.cl --target victim.lab:80 --cl1 6 --cl2 0
```

The default payloads match PortSwigger's reference bytes; see
[`examples/`](../examples/).

---

## 4. Fuzz mode

```
rawhttp --fuzz FILE --target host:port [--marker STR] [--crlf] [--tls] [options]
```

Marker-based mutation fuzzing. Takes a raw request template containing a
marker (default `FUZZ`), substitutes each corpus payload in turn, sends it,
and diffs the result against a **baseline** (the template with the marker
replaced by a neutral value).

| Flag | Meaning | Default |
|------|---------|---------|
| `--fuzz FILE` | Request template containing the marker. | — |
| `--target host:port` | Where to connect. | — |
| `--marker STR` | The text in `FILE` to replace each iteration. | `FUZZ` |

### Built-in corpus (12 payloads)

Empty, long-1000-`A`, long-10000-`A`, CRLF-injection, NUL byte, control
chars, path traversal, format string, SQL quote, overlong-UTF-8 NUL, negative
number, huge number.

### Anomaly flags

Each mutation is compared to the baseline on three axes; the raw numbers print
regardless, the flags just draw your eye:

- **`[status]`** — HTTP status code differs.
- **`[length]`** — response length differs by more than `max(10%, 50 bytes)`.
- **`[timing]`** — TTFB exceeds `3× baseline + 200 ms`.
- **`[send-failed]`** — the request itself errored (connection/timeout).

### Example

```sh
printf 'GET /search?q=FUZZ HTTP/1.1\r\nHost: victim\r\nConnection: close\r\n\r\n' > tmpl.txt
rawhttp --fuzz tmpl.txt --target victim.lab:80 --marker FUZZ
```

---

## 5. Scan mode

```
rawhttp --scan-file FILE [--concurrency N] [options]
```

Fetches many URLs concurrently via a pthread worker pool, printing one result
line per target **in input order**.

| Flag | Meaning | Default |
|------|---------|---------|
| `--scan-file FILE` | File of URLs, one per line. Blank lines and `#` comments are skipped. | — |
| `--concurrency N` | Number of worker threads. Clamped to `[1, target count]`. | `1` |

Each target is a full normal-mode `GET` (so it honors `--timeout`, `--proxy`,
`--insecure`). `--output json` emits a JSON array instead of the table.

### Example

```sh
cat > targets.txt <<'EOF'
# internal hosts
http://web1.lab/
http://web2.lab/health
https://web3.lab/
EOF

rawhttp --scan-file targets.txt --concurrency 8 --timeout 3000
rawhttp --scan-file targets.txt --concurrency 8 --output json > results.json
```

Table columns: `URL  STATUS  LEN  TTFB(ms)  TOTAL(ms)`; failed targets show
`-` and the error in parentheses.

---

## Output formats

`--output` controls normal- and scan-mode rendering.

- **`raw`** (default) — status line, headers, blank line, then the body
  written **byte-exactly** via `write()` (binary-safe; embedded NULs pass
  through).
- **`pretty`** — the same, with human separators (`--- HTTP/1.1 200 OK (N
  headers) ---`, `--- body (N bytes) ---`).
- **`json`** — one JSON object: `status`, `http_version`, `reason`,
  `headers[]`, and `body_base64` (the body is base64-encoded so binary bodies
  are lossless). Header/reason strings are JSON-escaped.

```sh
rawhttp --output json https://example.com/ | jq .status
```

---

## Timeouts

`--timeout MS` bounds three things with one value:

- **Connect** — via a non-blocking `connect()` + `poll()`. A hung SYN fails
  fast instead of blocking on the OS default (~2 min).
- **Each read** and **each write** — via `SO_RCVTIMEO` / `SO_SNDTIMEO`, which
  also bounds TLS I/O (it sits on the same fd).

A timeout surfaces as the error `operation timed out`. `0` disables all three
(classic blocking behavior).

```sh
rawhttp --timeout 2000 https://slow.example.com/   # give up after 2s
```

---

## Proxying (Burp / upstream)

`--proxy host:port` routes **every** connection (all modes) through an HTTP
`CONNECT` tunnel — point it at Burp to inspect exactly what rawhttp sends.

Because it tunnels the real `host:port`, TLS still terminates **end-to-end at
the target**, so certificate verification is unaffected.

```sh
rawhttp --proxy 127.0.0.1:8080 https://example.com/
rawhttp --proxy 127.0.0.1:8080 --smuggle cl.te --target victim.lab:80 --probe
```

A non-2xx `CONNECT` reply surfaces as `Connection failed`.

---

## Exit codes & stdout/stderr contract

- **Exit `0`** on success, **`1`** on any error (bad args, DNS/connect/TLS
  failure, parse error, timeout, limit exceeded).
- **stdout** carries only the payload you asked for — the response body/dump
  (raw/pretty), the JSON document, or the scan table. Safe to pipe.
- **stderr** carries everything else: the banner, `--timing` lines, progress
  (`--- sending N bytes ---`), logs, and errors.

```sh
rawhttp --output json https://example.com/ 2>/dev/null | jq .   # clean JSON
```

Log verbosity is compiled to warn-level by default; internal `LOG_*` macros
gate on a global level (wired for future `-v` flags).

---

## Safety limits

Hardening bounds that make malformed/hostile responses fail cleanly instead of
exhausting memory (all surface as `exceeded configured safety limit`):

| Limit | Value |
|-------|-------|
| Header block | 64 KiB |
| Chunk-size line | 1 KiB |
| Single chunk | 64 MiB |
| Total body | 512 MiB |

These apply to response parsing; raw-mode *sending* is never bounded — you
send exactly what you wrote.
