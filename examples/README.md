# Example raw payloads 

Byte-exact HTTP/1.1 requests (reat `\r\n` line endings, no `--crlf` needed) for use directly
with raw mode. These are reference material - the actual bytes matter here, so DON'T edit them with
a text editor that might rewrite line endings.

## basic_get.txt

A plain, well-formed GET request - useful as a sanity check that raw mode round-trips a normal
request correctly, and as a starting point to copy and mutate by hand.

```sh
./rawhttp --raw examples/basic_get.txt --target example.com:80
```

## smuggle_cl_te.txt

The canonical CT.TE desync payload (PortSwigger's own reference example): a front-end that 
trusts `Content-Length` forwards exactly 13 bytes to the back-end; a back-end that trusts 
`Transfer-Encoding` processes the `\0\r\n\r\n` as the end of the chunked body and treats the 
trailing `SMUGGLED` as the start of whatever request it reads next off the same connection.

```sh
./rawhttp --raw examples/smuggle_cl_te.txt --target target-host:80
```

Equivalent to (and generated the same way as):

```sh 
./rawhttp --smuggle cl.te --target  target-host:80
```

## smuggle_te_cl.txt

The mirror image : a front-end that trusts `Transfer-Encoding` processes the full chunked body
(one 8-byte chunk containing `SMUGGLED`, then the terminating chunk); a back-end that trusts
`Content-Length: 3` read only `8\r\n` as the body, leaving `SMUGGLED\r\n0\r\n\r\n` dangling as
the start of the next request it parses.

```sh
./rawhttp --raw examples/smuggle_te_cl.txt --target target-host:80
# or: ./rawhttp --smuggle te.cl --target target-host:80
```

## smuggle_cl_cl.txt

Two conflicting `Content-Length` headers (5 and 8, for an 8-byte body `helloXXX`) - which one
wins depends entirely on which header the front-end and back-end each pick, and disagreement
there is its own desync primitive distinct from CL.TE/TE.CL.

```sh
./rawhttp --raw examples/smuggle_cl_cl.txt --target target-host:80
# or: ./rawhttp --smuggle cl.cl --target target-host:80 --smuggled helloXXX --cl1 5 --cl2 8
```

## Legal

Only point these at hosts you own or are explicitly authorized to test. See the top-level
README for details.
