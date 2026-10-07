# Registry-proxy - Universal HTTP/HTTPS download cache/proxy speed multiplier


## Problem

Pulling images from a distant registry is slow even on a fast link. Every
round trip has to cross the distance and a single TCP stream can't fill
your bandwidth over that kind of latency.

## Solution

Tool splits each large layer of requested binary into chunks and fetches them in
parallel through [aria2](https://aria2.github.io/) which multiplies
effective throughput.

## Key features

- **Redirect-aware blob fetch**: the final CDN URL is resolved before the
  download starts. net/http drops the registry's bearer token on cross-host
  redirects, so it never reaches a third party.
- **aria2-accelerated downloads**: blobs at or above `min-aria2-size` go
  through aria2's `--split`/`--max-connection-per-server`. Smaller ones are
  fetched directly, where the parallelism would only add overhead.
- **DNS-isolated aria2 RPC server**: aria2c always runs inside a container (see
  `docker/aria2`), with `/etc/hosts` emptied and `/etc/resolv.conf` pinned
  to the host's real nameserver providing isolation.
- **Content-addressed cache**: blobs are keyed by digest, so a layer shared
  across repos or registries is downloaded once. sha256 blobs are verified
  by aria2's own `--checksum`, and concurrent requests for the same digest
  share a single in-flight download.
- **Generic downloads**: `/fetch?url=...` sends any HTTP/HTTPS URL through
  the same accelerated, cached pipeline, keyed by the URL's sha256.

Manifests and tag listings pass through unmodified and uncached.

## Requirements

- Docker (runs aria2c; `install.sh` builds the image from `docker/aria2`)
- Go 1.22+ (to build from source)

```sh
# Debian/Ubuntu
sudo apt install golang-go docker.io

# Arch Linux
sudo pacman -S go docker
```

## Config file

All settings live in `~/registry-proxy/config`, one `key = value` per line.
Blank lines and `#` comments are ignored. A missing file, or a missing key,
falls back to the built-in default.

```
listen = :5000
cache-dir = /var/cache/registry-proxy
aria2-rpc-port = 6880
aria2-connections = 16
aria2-min-split-size = 5M
min-aria2-size = 1048576
http-timeout = 30s
insecure-registries = my.registry:5000,another:5000
mitm-tls = true
ca-dir = ~/registry-proxy/ca
```

| Key | Default | Meaning |
|---|---|---|
| `listen` | `:5000` | Address to listen on |
| `cache-dir` | `~/registry-proxy/cache` | Blob cache + in-progress downloads |
| `aria2-rpc-port` | `6880` | aria2 JSON-RPC port, reachable on the host via `--network host` |
| `aria2-connections` | `16` | Max connections per server for aria2 |
| `aria2-min-split-size` | `5M` | aria2 `-k` |
| `min-aria2-size` | `1048576` | Blobs smaller than this bypass aria2 |
| `http-timeout` | `30s` | Timeout for manifest/tag/HEAD requests |
| `insecure-registries` | (none) | Comma-separated hosts to contact over plain HTTP; `*` for all |
| `mitm-tls` | `false` | Enable transparent-HTTPS CA termination (see below) |
| `ca-dir` | `./ca` | Directory holding `ca-cert.pem`/`ca-key.pem` for `mitm-tls` |

## Build

```sh
go build -o registry-proxy ./cmd/registry-proxy
```

## Installation

From the repo root:
```sh
./install.sh
sudo systemctl daemon-reload
sudo systemctl enable --now registry-proxy
```

It also redirects ports 80 and 443 to the proxy from the unit itself,
whether or not `mitm-tls` is on - see
[Transparent HTTPS](#transparent-https-mitm) for what that's for. As
root it needs no `setcap` step.


## Using the proxy

Point any client at `localhost:5000` and put the upstream
host first in the repo path. That's the whole client-side setup. Because
this is a universal HTTP pull-through proxy rather than a client-specific
one, plain HTTP tools can fetch raw blobs just as well:

```sh
curl -L http://localhost:5000/v2/nginx/blobs/sha256:<digest> -o layer.tar.gz
wget https://localhost:5000/v2/gcr.io/google-containers/pause/blobs/sha256:<digest>
```

On the registry side the proxy understands `/v2/...` paths only; it is not a
transparent forward proxy. Every client has to be aimed at `localhost:5000`
explicitly, either on the command line or through its own registry-mirror
setting. Nothing is intercepted for you.

In particular, pointing a registry host at `127.0.0.1` in `/etc/hosts` does
**not** make `docker pull`, `crane pull`, and friends work. Registry routing
is path-based, keyed off the repo path's leading component
(`ResolveUpstream`), not off the request's `Host` header - a request that
arrives with the registry's native path and no host prefix has nothing to
resolve. Use `localhost:5000/<repo>` instead.

Plain `wget`/`curl` against an `/etc/hosts`-redirected HTTPS host *can* be
made to work, certificate included, via the transparent-HTTPS setup below.
That one installs a locally-trusted CA, so it stays opt-in and is documented
on its own.

System-wide `HTTP_PROXY`/`HTTPS_PROXY` variables won't do anything either.
The proxy implements no `CONNECT` method and therefore can't serve as a
classic forward proxy for arbitrary destinations.

## Generic HTTP/HTTPS downloads

The `/fetch` endpoint takes any URL, not just registry blobs, and runs it
through the same accelerated, cached pipeline - keyed by the URL's own
sha256 rather than a content digest:

```sh
curl -L "http://localhost:5000/fetch?url=https://example.com/downloads/file.tar.gz" -o file.tar.gz
wget "http://localhost:5000/fetch?url=https://example.com/downloads/file.tar.gz"
```

A tool still has to be pointed at this URL explicitly, through its own
proxy/mirror/download-URL setting. A bare `wget https://example.com/...` is
not intercepted.

### Docker

To stop prefixing every image with `localhost:5000/`, register the proxy as
a Docker registry mirror:

```sh
sudo mkdir -p /etc/docker
sudo tee /etc/docker/daemon.json <<'EOF'
{
  "registry-mirrors": ["http://localhost:5000"],
  "insecure-registries": ["localhost:5000"]
}
EOF
sudo systemctl restart docker
```

Verify the mirror is active:

```sh
docker info --format '{{.RegistryConfig.Mirrors}}'
```

`docker pull ...` now goes through the proxy automatically. Note that
Docker's mirror mechanism covers Docker Hub (`docker.io`) only. Pulls from
`gcr.io`, `quay.io`, and the rest still need the explicit
`localhost:5000/<registry-host>/...` prefix, because routing is path-based.

## Transparent HTTPS (MITM)

**Security-relevant, opt-in.** This mode requires a self-signed root CA that
*you* generate and install into a client's trust store. Anything trusting
that CA will accept certificates it signs for *any* hostname. Only do this
on machines you control, and only route hosts you trust through it.

Once it's on, redirecting a host to the proxy - with `/etc/hosts` or an
iptables rule - is enough to make a plain, unmodified request work.

The proxy terminates the client's TLS with a certificate it signs on the fly
for whatever `Host` the request names, then fetches and caches `Host` + path
internally, exactly as `/fetch?url=...` does.

Enable it in the config file:

```
mitm-tls = true
ca-dir = ~/registry-proxy/ca
```

### Generating the CA

[`generate-ca.sh`](generate-ca.sh) creates a root CA and writes it to
`~/registry-proxy/ca` by default or a path given as the first
argument:

```sh
./generate-ca.sh
```

Then follow the trust-store install instructions it prints at the end.

## How to use

Everything below uses `ash-speed.hetzner.com` as the example host, because
Hetzner publishes test files big enough to show the speed difference.
Substitute whatever host you actually want to route through the proxy - the
steps are the same.

**1. Add a `127.0.0.1` entry in `/etc/hosts`:

```sh
127.0.0.1 tyo.download.datapacket.com
```

Every DNS lookup for that hostname now returns localhost.

**2. Redirect ports 80 and 443 to the proxy.** One listen port serves both
protocols: the proxy sniffs the first byte of each connection - `0x16` marks
a TLS `ClientHello` - and hands it to either the plain or the
TLS-terminating handler. That's what lets both ports point at the *same*
proxy port:

```sh
sudo iptables -t nat -A OUTPUT -d 127.0.0.1 -p tcp --dport 80  -j REDIRECT --to-port 5000
sudo iptables -t nat -A OUTPUT -d 127.0.0.1 -p tcp --dport 443 -j REDIRECT --to-port 5000
```

`-d 127.0.0.1` scopes each rule to loopback-destined traffic, real outbound HTTPS to other IPs
is left alone.


## Benchmarks

** Without registry-proxy: **
```sh
time  wget https://tyo.download.datapacket.com/1000mb.bin
real	4m19.443s
user	0m0.109s
sys	0m0.259s
```

** Using registry-proxy: **
```sh
time  wget https://tyo.download.datapacket.com/1000mb.bin
real	2m42.123s
user	0m0.173s
sys	0m0.499s
```

## Caveats:
1. Some servers don't allow multiple simultaneous connections and chunking.
Check it before using this tool, try to tune `retry_time` for `aria2c`.

## License

[GPL-3.0](LICENSE)

---

Contributions are welcome. If the project is useful to you, a star helps.
