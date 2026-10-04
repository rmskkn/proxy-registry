# Registry-proxy

Universal HTTP pull-through proxy for container registries (OCI
Distribution / Registry HTTP API v2).
Resolves the real upstream per request, follows registry -> CDN redirects,
and downloads large blobs with [aria2](https://aria2.github.io/) over
multiple connections for speed. Single Go binary. Download-only, no push support.

## Problem

Pulling images across long distances - say, a server in the UK pulling from a
CDN in Japan - can be slow even with a fast connection, simply because the
data has so far to travel on every round trip. A single download can't use
your full bandwidth over that kind of distance. This proxy splits each large
layer into chunks and downloads them over many connections at once via
aria2, multiplying effective speed. Once downloaded, the layer is cached, so
the next pull - from any host, registry, or repo using that same layer - is
instant.

## How it works

- **Universal routing**: the repo name's leading path component names the
  upstream registry host, e.g. `proxy.local/nginx` -> `docker.io/library/nginx`,
  `proxy.local/gcr.io/google-containers/pause` -> `gcr.io/google-containers/pause`.
  Any registry speaking the standard OCI/registry token-auth challenge works
  without extra configuration.
- **Redirect-aware blob fetch**: resolves the final CDN URL before
  downloading (net/http drops the registry's bearer token automatically on
  cross-host redirects, so it's never leaked to a third party).
- **aria2-accelerated downloads**: blobs at or above `min-aria2-size` use
  aria2's `--split`/`--max-connection-per-server`; smaller ones are fetched
  directly.
- **Content-addressed cache**: blobs are cached by digest, so a layer shared
  across repos or registries is only downloaded once. sha256 blobs are
  verified by aria2's own `--checksum`; concurrent requests for the same
  digest share one in-flight download.
- **Generic downloads**: `/fetch?url=...` runs any HTTP/HTTPS URL through
  the same aria2-accelerated, cached pipeline, keyed by the URL's sha256.

Manifests and tag listings are passed through unmodified and uncached.

## Requirements

- `aria2c` (package `aria2`)

## Config file

All settings come from `~/registry-proxy/config`, one `key = value` per line
(blank lines and `#` comments ignored). Missing file or keys fall back to
built-in defaults.

```
listen = :5000
cache-dir = /var/cache/registry-proxy
aria2-path = aria2c
aria2-rpc-port = 6880
aria2-connections = 32
aria2-min-split-size = 5M
min-aria2-size = 1048576
http-timeout = 30s
insecure-registries = my.registry:5000,another:5000
```

| Key | Default | Meaning |
|---|---|---|
| `listen` | `:5000` | Address to listen on |
| `cache-dir` | `./cache` | Blob cache + in-progress downloads |
| `aria2-path` | `aria2c` | Path to the aria2c binary |
| `aria2-rpc-port` | `6880` | Local aria2 JSON-RPC port |
| `aria2-connections` | `16` | Max connections per server for aria2 |
| `aria2-min-split-size` | `5M` | aria2 `-k` |
| `min-aria2-size` | `1048576` | Blobs smaller than this bypass aria2 |
| `http-timeout` | `30s` | Timeout for manifest/tag/HEAD requests |
| `insecure-registries` | (none) | Comma-separated hosts to contact over plain HTTP; `*` for all |

## Installation

Run the following script from the repo root:
```sh
./install.sh   # builds the binary, writes a default ~/registry-proxy/config if missing
./registry-proxy
```

Or manually:

```sh
go build -o registry-proxy ./cmd/registry-proxy
mkdir -p ~/registry-proxy && echo "cache-dir = /var/cache/registry-proxy" > ~/registry-proxy/config
./registry-proxy
```

```sh
crane pull localhost:5000/nginx:latest nginx.tar
crane pull localhost:5000/gcr.io/google-containers/pause:3.9 pause.tar
```

## Using the proxy

Any OCI/registry-API client works by pointing it at `localhost:5000` with
the upstream host as the repo path's leading component - no client-specific
setup required beyond that. Raw blobs can also be fetched with plain
HTTP/HTTPS tools, since this is a universal HTTP pull-through proxy, not
tied to one client:

```sh
curl -L http://localhost:5000/v2/nginx/blobs/sha256:<digest> -o layer.tar.gz
wget https://localhost:5000/v2/gcr.io/google-containers/pause/blobs/sha256:<digest>
```

The proxy only understands `/v2/...` registry paths - it's not a transparent
forward proxy. Each client must be pointed at `localhost:5000` explicitly;
nothing redirects automatically unless the client itself is configured
(e.g. a registry-mirror setting) to send requests there.

Adding a registry host to `/etc/hosts` pointing at `127.0.0.1` does **not**,
by itself, make registry pulls (`docker pull`, `crane pull`, etc.) work:
registry-API routing is path-based, keyed off the repo path's leading
component (`ResolveUpstream`), not the request's `Host` header. A request
that arrives with the real registry's native path (no host prefix) can't be
resolved that way. Point registry clients at `localhost:5000/<repo>`
directly instead.

Plain `wget`/`curl` against an arbitrary HTTPS host redirected via
`/etc/hosts` *can* be made to work, including the certificate, with the
transparent-HTTPS setup below - that's a bigger, security-relevant change
(installing a locally-trusted CA), so it's opt-in and documented separately.

Setting system-wide `HTTP_PROXY`/`HTTPS_PROXY` env vars to point at the
proxy does **not** work: the proxy implements no `CONNECT` method, so it
can't act as a classic forward proxy for arbitrary destinations that way.

## Generic HTTP/HTTPS downloads

For any URL, not just registry blobs, use the `/fetch` endpoint - it runs
the same aria2-accelerated, cached pipeline, keyed by the URL's own sha256
instead of a content digest:

```sh
curl -L "http://localhost:5000/fetch?url=https://example.com/downloads/file.tar.gz" -o file.tar.gz
wget "http://localhost:5000/fetch?url=https://example.com/downloads/file.tar.gz"
```

A tool must still be pointed at this URL explicitly (via its own
proxy/mirror/download-URL setting, same as above) - there is still no
system-wide interception of plain `wget https://example.com/...` calls.

### Docker

To avoid prefixing every image with `localhost:5000/`, point the Docker
daemon at the proxy as a registry mirror. Edit (or create)
`/etc/docker/daemon.json`:

```json
{
  "registry-mirrors": ["http://localhost:5000"],
  "insecure-registries": ["localhost:5000"]
}
```

Restart Docker:

```sh
sudo systemctl restart docker
```

`docker pull nginx` now goes through the proxy automatically. This only
covers Docker Hub (`docker.io`) - Docker's mirror mechanism doesn't apply to
other registries. Pulls from `gcr.io`, `quay.io`, etc. still need the
explicit `localhost:5000/<registry-host>/...` prefix, since routing is
path-based.

## Transparent HTTPS (MITM)

**Security-relevant, opt-in.** This installs a self-signed root CA, which
*you* generate and provide, into a client's trust store. Anything that
trusts that CA will accept certificates it signs for *any* hostname - only
do this on machines you control, and only point hosts you trust through it.

With this enabled, redirecting a host to the proxy - via `/etc/hosts` or an
iptables rule - makes a plain, unmodified request work with no per-call
changes, no `/v2/...` or `/fetch?url=...` involved:

```sh
wget https://example.com/downloads/file.tar.gz
```

The proxy terminates the client's TLS with a certificate it signs on the
fly for whatever `Host` the request names, then fetches and caches
`Host` + path internally the same way `/fetch?url=...` does.

Enable it in the config file:

```
mitm-tls = true
ca-dir = ~/registry-proxy/ca
```

The proxy does **not** generate this CA itself - it only loads one you
already placed in `ca-dir` as `ca-cert.pem` / `ca-key.pem`. Start without
both files present and it fails to start, naming the missing file.

### Generating the CA

Generate a root CA with openssl and write it to `ca-dir`:

```sh
mkdir -p ~/registry-proxy/ca
openssl req -x509 -newkey rsa:2048 -sha256 -days 360 -nodes \
  -keyout ~/registry-proxy/ca/ca-key.pem \
  -out ~/registry-proxy/ca/ca-cert.pem \
  -subj "/CN=registry-proxy local CA/O=registry-proxy" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign,digitalSignature"
```

Then install that certificate into the trust store of every client you
want this to work for:

```sh
# Debian/Ubuntu
sudo cp ~/registry-proxy/ca/ca-cert.pem /usr/local/share/ca-certificates/registry-proxy.crt
sudo update-ca-certificates

# Arch Linux
sudo cp ~/registry-proxy/ca/ca-cert.pem /etc/ca-certificates/trust-source/anchors/registry-proxy.crt
sudo trust extract-compat
```

The proxy's single listen port serves both protocols - it sniffs the first
byte of each connection (`0x16` means a TLS `ClientHello`) and dispatches to
a plain or TLS-terminating handler accordingly. That's what makes it
possible to redirect both port 80 and port 443 at the *same* proxy port:

```sh
sudo iptables -t nat -A OUTPUT -d 127.0.0.1 -p tcp --dport 80  -j REDIRECT --to-port 5000
sudo iptables -t nat -A OUTPUT -d 127.0.0.1 -p tcp --dport 443 -j REDIRECT --to-port 5000
```

(`-d 127.0.0.1` scopes the rule to loopback-destined traffic, i.e. hosts
you've already redirected via `/etc/hosts` - it won't touch real outbound
HTTPS traffic to other IPs.)

Note this caches by URL, not registry digest - registry-specific behavior
(digest-addressed caching, CDN-redirect auth stripping) doesn't apply to
registry hosts reached this way.

## License

[GPL-3.0](LICENSE)

---

Contributions are welcome. If this project is useful to you, consider
starring the repository.
