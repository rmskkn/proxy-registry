// Package proxy implements the pull-relevant subset of the Docker Registry
// HTTP API v2 and resolves every request against whatever upstream registry
// the client's repo name points at.
package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"log"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"registry-proxy/internal/aria2"
	"registry-proxy/internal/auth"
	"registry-proxy/internal/cache"
	"registry-proxy/internal/config"
	"registry-proxy/internal/registry"
	"registry-proxy/internal/singleflight"
)

// Proxy implements http.Handler for the pull-relevant subset of the Docker
// Registry HTTP API v2 (see registry.ParseV2Path / registry.ResolveUpstream).
type Proxy struct {
	cfg       *config.Config
	cache     *cache.Cache
	aria2     *aria2.Aria2
	auth      *auth.Authenticator
	blobGroup *singleflight.Group

	// genericClient is used only by the generic-fetch pipeline (fetchGeneric,
	// fetchDirectGeneric): it dials through dialBypassingHosts so a host
	// locally redirected at this proxy still reaches the real upstream when
	// the proxy itself is the one making the request. See realdns.go.
	genericClient *http.Client
}

// New builds a Proxy backed by cache for blob storage and aria2 for
// accelerated large-blob downloads.
func New(cfg *config.Config, c *cache.Cache, a *aria2.Aria2) *Proxy {
	au := auth.New(&http.Client{Timeout: cfg.HTTPTimeout})
	if cfg.NetrcPath != "" {
		if err := au.LoadNetrc(cfg.NetrcPath); err != nil && !os.IsNotExist(err) {
			log.Printf("loading netrc-path %s: %v", cfg.NetrcPath, err)
		}
	}
	return &Proxy{
		cfg:       cfg,
		cache:     c,
		aria2:     a,
		auth:      au,
		blobGroup: singleflight.NewGroup(),
		genericClient: &http.Client{
			Timeout:   cfg.HTTPTimeout,
			Transport: &http.Transport{DialContext: dialBypassingHosts},
		},
	}
}

// basicAuthFor returns an Authorization header value for rawURL's host, from
// netrc credentials loaded at startup, if any.
func (p *Proxy) basicAuthFor(rawURL string) (string, bool) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", false
	}
	return p.auth.BasicAuth(u.Hostname())
}

// basicCredsFor returns netrc credentials for rawURL's host unencoded, for
// the aria2 path - see aria2.BasicCreds for why that path can't use the
// header basicAuthFor builds.
func (p *Proxy) basicCredsFor(rawURL string) *aria2.BasicCreds {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	login, password, ok := p.auth.BasicCreds(u.Hostname())
	if !ok {
		return nil
	}
	return &aria2.BasicCreds{User: login, Password: password}
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/fetch" {
		p.handleFetch(w, r)
		return
	}
	if r.URL.Path == "/v2/" || r.URL.Path == "/v2" {
		w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{}"))
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/v2/") {
		if p.cfg.MITM {
			// Plain HTTP side of a transparently redirected host (e.g. port 80
			// iptables-REDIRECTed here alongside 443): same pipeline as
			// ServeMITM's TLS side, just without a cert to terminate.
			p.fetchURL(w, r, "http://"+r.Host+r.URL.RequestURI())
			return
		}
		http.NotFound(w, r)
		return
	}
	req, err := registry.ParseV2Path(r.URL.Path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	host, repo := registry.ResolveUpstream(req.Name)
	scheme := registry.UpstreamScheme(p.cfg, host)

	switch req.Kind {
	case "manifest":
		p.proxyMetadata(w, r, fmt.Sprintf("%s://%s/v2/%s/manifests/%s", scheme, host, repo, req.Arg))
	case "tags":
		p.proxyMetadata(w, r, fmt.Sprintf("%s://%s/v2/%s/tags/list", scheme, host, repo))
	case "blob":
		p.handleBlob(w, r, scheme, host, repo, req.Arg)
	default:
		http.NotFound(w, r)
	}
}

// proxyMetadata transparently forwards small, non-cacheable registry API
// calls (manifests, tag listings) to the upstream, preserving the Accept
// header docker uses to pick a manifest schema and the digest/content-type
// headers it uses to validate the response. Not aria2-accelerated: these
// payloads are kilobytes, not the bottleneck in a pull.
func (p *Proxy) proxyMetadata(w http.ResponseWriter, r *http.Request, upstreamURL string) {
	req, err := http.NewRequest(r.Method, upstreamURL, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if accept := r.Header.Get("Accept"); accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := p.auth.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for _, h := range []string{"Content-Type", "Docker-Content-Digest", "Docker-Distribution-Api-Version", "Content-Length"} {
		if v := resp.Header.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (p *Proxy) handleBlob(w http.ResponseWriter, r *http.Request, scheme, host, repo, digest string) {
	upstreamURL := fmt.Sprintf("%s://%s/v2/%s/blobs/%s", scheme, host, repo, digest)

	if r.Method == http.MethodHead {
		if fi, err := p.cache.Stat(digest); err == nil {
			w.Header().Set("Content-Length", fmt.Sprintf("%d", fi.Size()))
			w.Header().Set("Docker-Content-Digest", digest)
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			return
		}
		req, _ := http.NewRequest(http.MethodHead, upstreamURL, nil)
		resp, err := p.auth.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for _, h := range []string{"Content-Type", "Content-Length", "Docker-Content-Digest"} {
			if v := resp.Header.Get(h); v != "" {
				w.Header().Set(h, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		return
	}

	if !p.cache.Has(digest) {
		err := p.blobGroup.Do(digest, func() error {
			if p.cache.Has(digest) { // a concurrent caller may have just finished
				return nil
			}
			return p.fetchBlob(r.Context(), upstreamURL, digest)
		})
		if err != nil {
			log.Printf("blob fetch failed for %s: %v", digest, err)
			http.Error(w, "failed to fetch blob from upstream", http.StatusBadGateway)
			return
		}
	}
	p.serveCached(w, r, digest)
}

// serveCached streams a cached blob to the client. http.ServeContent handles
// Range requests and Content-Length/Last-Modified bookkeeping for us.
func (p *Proxy) serveCached(w http.ResponseWriter, r *http.Request, digest string) {
	f, fi, err := p.cache.Open(digest)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer f.Close()
	w.Header().Set("Docker-Content-Digest", digest)
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, "", fi.ModTime(), f)
}

// handleFetch serves an arbitrary HTTP/HTTPS URL through the same
// aria2-accelerated, cached download pipeline used for registry blobs, for
// clients that don't speak the Docker Registry HTTP API v2 at all. The
// cache key is the sha256 of the URL itself - there's no content digest to
// key on like a registry blob has - so a given URL is only downloaded once.
func (p *Proxy) handleFetch(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("url")
	if raw == "" {
		http.Error(w, "missing url parameter", http.StatusBadRequest)
		return
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		http.Error(w, "url must be http or https", http.StatusBadRequest)
		return
	}
	p.fetchURL(w, r, raw)
}

// ServeMITM handles a request received over a TLS connection terminated
// with a locally-trusted CA (see internal/mitmca): any host pointed at the
// proxy out-of-band (e.g. via /etc/hosts) is fetched and cached exactly
// like /fetch?url=..., keyed by the URL reconstructed from the request.
func (p *Proxy) ServeMITM(w http.ResponseWriter, r *http.Request) {
	raw := "https://" + r.Host + r.URL.RequestURI()
	p.fetchURL(w, r, raw)
}

// fetchURL serves raw through the content-addressed-by-URL cache, fetching
// it on a cache miss. Shared by handleFetch and ServeMITM - they differ
// only in how raw is obtained and validated.
func (p *Proxy) fetchURL(w http.ResponseWriter, r *http.Request, raw string) {
	cacheKey := fmt.Sprintf("url:%x", sha256.Sum256([]byte(raw)))

	if r.Method == http.MethodHead {
		if fi, err := p.cache.Stat(cacheKey); err == nil {
			w.Header().Set("Content-Length", fmt.Sprintf("%d", fi.Size()))
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		return
	}

	headerSent := false
	var discoveredHeaders http.Header
	if !p.cache.Has(cacheKey) {
		// Early 200 is gated on onStarted (real progress), not addUri's gid,
		// so a URL that 404s upstream doesn't get a 200 already sent.
		onStarted := func(totalLength int64, headers http.Header) {
			headerSent = true
			copyForwardableHeaders(w.Header(), headers)
			if totalLength > 0 {
				w.Header().Set("Content-Length", strconv.FormatInt(totalLength, 10))
			}
			w.WriteHeader(http.StatusOK)
			if fl, ok := w.(http.Flusher); ok {
				fl.Flush()
			}
		}
		err := p.blobGroup.Do(cacheKey, func() error {
			if p.cache.Has(cacheKey) { // a concurrent caller may have just finished
				return nil
			}
			headers, err := p.fetchGeneric(r.Context(), raw, cacheKey, onStarted)
			discoveredHeaders = headers
			return err
		})
		if err != nil {
			if headerSent {
				// The status is already committed to the wire; nothing left
				// to do but close the connection without a body.
				log.Printf("fetch failed for %s after headers were already sent: %v", raw, err)
				return
			}
			var use *upstreamStatusError
			if errors.As(err, &use) {
				log.Printf("fetch failed for %s: %v", raw, err)
				http.Error(w, use.text, use.status)
				return
			}
			log.Printf("fetch failed for %s: %v", raw, err)
			http.Error(w, "failed to fetch url", http.StatusBadGateway)
			return
		}
	}

	if headerSent {
		f, _, err := p.cache.Open(cacheKey)
		if err != nil {
			log.Printf("opening cache entry for %s after headers were already sent: %v", raw, err)
			return
		}
		defer f.Close()
		io.Copy(w, f)
		return
	}

	// http.ServeContent only sniffs a Content-Type when none is set yet, and
	// its sniffer has no notion of JSON - a JSON body comes back as
	// "text/plain; charset=utf-8", which a strict client (e.g. Conan's API
	// responses) rejects. discoveredHeaders is only set by a fresh fetch
	// this request just performed - a pure cache hit (or a follower that
	// waited out someone else's singleflight.Do) never calls fetchGeneric at
	// all, so fall back to what the entry's actual fetch persisted.
	if discoveredHeaders == nil {
		if data, err := p.cache.ReadMeta(cacheKey); err == nil {
			discoveredHeaders, _ = decodeHeaders(data)
		}
	}
	if discoveredHeaders != nil {
		copyForwardableHeaders(w.Header(), discoveredHeaders)
	}
	f, fi, err := p.cache.Open(cacheKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer f.Close()
	http.ServeContent(w, r, "", fi.ModTime(), f)
}

// upstreamStatusError carries a definite status code the upstream itself
// returned, so fetchURL can pass it straight through to the client instead
// of flattening every failure into a generic 502.
type upstreamStatusError struct {
	status int
	text   string
}

func (e *upstreamStatusError) Error() string { return fmt.Sprintf("upstream returned %s", e.text) }

// logDownloadStart records that a download is starting, omitting the size
// when it isn't known (size < 0) rather than printing a meaningless -1.
// logDownloadStart records that a download is starting, omitting the size
// when it isn't known (size < 0) rather than printing a meaningless -1. It
// returns a func the caller runs on success, so "downloading" never goes
// unanswered in the log - it either resolves to "downloaded" or, on error,
// to whatever the caller already logs for that failure.
func logDownloadStart(what string, size int64) func() {
	start := time.Now()
	if size < 0 {
		log.Printf("downloading %s", what)
	} else {
		log.Printf("downloading %s (%d bytes)", what, size)
	}
	return func() {
		log.Printf("downloaded %s in %s", what, time.Since(start).Round(time.Millisecond))
	}
}

func upstreamError(status int) error {
	return &upstreamStatusError{status: status, text: fmt.Sprintf("%d %s", status, http.StatusText(status))}
}

// ariaStatusRe extracts the HTTP status aria2 reports in its own error text
// (e.g. "The response status is not successful. status=404").
var ariaStatusRe = regexp.MustCompile(`status=(\d+)`)

// ariaUpstreamError maps an aria2 download failure to the client-facing
// HTTP status; unmapped codes stay as-is and surface as a 502.
func ariaUpstreamError(err error) error {
	var de *aria2.DownloadError
	if !errors.As(err, &de) {
		return err
	}
	if m := ariaStatusRe.FindStringSubmatch(de.Message); m != nil {
		if code, convErr := strconv.Atoi(m[1]); convErr == nil && code >= 400 && code <= 599 {
			return fmt.Errorf("%w: %v", upstreamError(code), de)
		}
	}
	switch de.Code {
	case 3: // resource not found
		return fmt.Errorf("%w: %v", upstreamError(http.StatusNotFound), de)
	case 24: // HTTP authorization failed
		return fmt.Errorf("%w: %v", upstreamError(http.StatusUnauthorized), de)
	}
	return err
}

// fetchGeneric downloads an arbitrary URL, routing through aria2 above
// min-aria2-size and fetching directly below it, mirroring fetchBlob - but
// with no digest to verify against, since the URL carries no content hash.
//
// The preflight HEAD below, and fetchDirectGeneric's own GET, both go out
// through p.genericClient (dialBypassingHosts, see realdns.go): when
// rawURL's host has been pointed at this same proxy out-of-band (the MITM
// use case), the ordinary system resolver would loop the request back into
// the proxy itself instead of reaching the real upstream, since the target
// is (correctly) not cached yet. aria2 sidesteps the same problem for its
// own downloads via its own DNS isolation; genericClient does the
// equivalent for these two direct requests, so their size and headers are
// trustworthy instead of reflecting the proxy's own 404.
func (p *Proxy) fetchGeneric(ctx context.Context, rawURL, cacheKey string, onStarted func(totalLength int64, headers http.Header)) (http.Header, error) {
	size := int64(-1)
	var headers http.Header
	if headReq, err := http.NewRequest(http.MethodHead, rawURL, nil); err == nil {
		if hdr, ok := p.basicAuthFor(rawURL); ok {
			headReq.Header.Set("Authorization", hdr)
		}
		if resp, err := p.genericClient.Do(headReq); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				size = resp.ContentLength
				headers = resp.Header
			}
		}
	}

	done := logDownloadStart(rawURL, size)

	var err error
	if size >= 0 && size < p.cfg.MinAria2Size {
		err = p.fetchDirectGeneric(rawURL, cacheKey, size)
	} else {
		err = p.fetchWithAria2Generic(ctx, rawURL, cacheKey, headers, onStarted)
	}
	if err == nil {
		done()
		if headers != nil {
			if werr := p.cache.WriteMeta(cacheKey, encodeHeaders(headers)); werr != nil {
				log.Printf("writing header metadata for %s: %v", rawURL, werr)
			}
		}
	}
	return headers, err
}

// hopByHopHeaders names headers that are connection-scoped (RFC 7230 §6.1)
// or that fetchURL/http.ServeContent already derive themselves from the
// actual transfer - these must never be copied verbatim from an upstream
// HEAD onto the response for a different connection and body.
var hopByHopHeaders = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Te":                  true,
	"Trailer":             true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
	"Content-Length":      true,
	"Date":                true,
}

// copyForwardableHeaders sets every header from src onto dst except the
// ones in hopByHopHeaders.
func copyForwardableHeaders(dst http.Header, src http.Header) {
	for k, v := range src {
		if hopByHopHeaders[k] {
			continue
		}
		dst[k] = v
	}
}

// encodeHeaders serializes h as a MIME-style header block, for persisting
// alongside a cached generic-fetch entry (see cache.WriteMeta) - a second
// request for the same URL that lands on a pure cache hit never calls
// fetchGeneric again, so without this it would fall back to
// http.ServeContent's sniffing every time, the exact mismatch
// (JSON sniffed as text/plain) this header-forwarding fix exists for.
func encodeHeaders(h http.Header) []byte {
	var buf bytes.Buffer
	for k, vs := range h {
		for _, v := range vs {
			buf.WriteString(k)
			buf.WriteString(": ")
			buf.WriteString(v)
			buf.WriteString("\r\n")
		}
	}
	buf.WriteString("\r\n")
	return buf.Bytes()
}

// decodeHeaders parses what encodeHeaders wrote.
func decodeHeaders(data []byte) (http.Header, error) {
	tp := textproto.NewReader(bufio.NewReader(bytes.NewReader(data)))
	mh, err := tp.ReadMIMEHeader()
	if err != nil {
		return nil, err
	}
	return http.Header(mh), nil
}

func (p *Proxy) fetchDirectGeneric(rawURL, cacheKey string, size int64) error {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	if hdr, ok := p.basicAuthFor(rawURL); ok {
		req.Header.Set("Authorization", hdr)
	}
	resp, err := p.genericClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return upstreamError(resp.StatusCode)
	}
	limited := io.LimitReader(resp.Body, size+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	if int64(len(data)) != size {
		return fmt.Errorf("short read: expected %d bytes, got %d", size, len(data))
	}
	return p.cache.Write(cacheKey, data)
}

func (p *Proxy) fetchWithAria2Generic(ctx context.Context, rawURL, cacheKey string, headers http.Header, onStarted func(totalLength int64, headers http.Header)) error {
	dir := p.cache.TmpDir()
	out := p.cache.TmpName(cacheKey)
	wrapped := func(totalLength int64) {
		if onStarted != nil {
			onStarted(totalLength, headers)
		}
	}
	if err := p.aria2.Download(ctx, rawURL, nil, p.basicCredsFor(rawURL), dir, out, p.cfg.Aria2Connections, p.cfg.Aria2MinSplit, "", wrapped); err != nil {
		return ariaUpstreamError(err)
	}
	return p.cache.Commit(cacheKey, filepath.Join(dir, out))
}

// fetchBlob resolves the blob's real download location - following any
// registry -> CDN redirect, which Docker Hub and others use for layer
// storage - and retrieves it, using aria2 to parallelize the transfer for
// anything above the small-blob threshold, then commits it into the
// content-addressed cache. Only one fetch per digest runs at a time, see
// blobGroup in handleBlob.
func (p *Proxy) fetchBlob(ctx context.Context, upstreamURL, digest string) error {
	headReq, _ := http.NewRequest(http.MethodHead, upstreamURL, nil)
	resp, err := p.auth.Do(headReq)
	if err != nil {
		return fmt.Errorf("resolving blob location: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("upstream HEAD returned %s", resp.Status)
	}

	// resp.Request is the last request actually sent, after following any
	// redirects; net/http strips Authorization automatically when a
	// redirect crosses hosts, so finalAuth is only non-empty when it's
	// still valid for finalURL's host.
	finalURL := resp.Request.URL.String()
	finalAuth := resp.Request.Header.Get("Authorization")
	size := resp.ContentLength

	alg, hexDigest, ok := cache.SplitDigest(digest)
	if !ok {
		return fmt.Errorf("unsupported digest %q", digest)
	}

	done := logDownloadStart(digest, size)

	if size >= 0 && size < p.cfg.MinAria2Size {
		err = p.fetchDirect(finalURL, finalAuth, alg, hexDigest, digest, size)
	} else {
		err = p.fetchWithAria2(ctx, finalURL, finalAuth, alg, hexDigest, digest)
	}
	if err == nil {
		done()
	}
	return err
}

func (p *Proxy) fetchDirect(finalURL, auth, alg, hexDigest, digest string, size int64) error {
	req, _ := http.NewRequest(http.MethodGet, finalURL, nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := p.auth.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("upstream GET returned %s", resp.Status)
	}
	// Guard against a lying/absent Content-Length: never buffer more than
	// one small-blob threshold's worth in memory.
	limited := io.LimitReader(resp.Body, size+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	if int64(len(data)) != size {
		return fmt.Errorf("short read: expected %d bytes, got %d", size, len(data))
	}
	if err := verifyDigest(alg, hexDigest, data); err != nil {
		return err
	}
	return p.cache.Write(digest, data)
}

func (p *Proxy) fetchWithAria2(ctx context.Context, finalURL, auth, alg, hexDigest, digest string) error {
	dir := p.cache.TmpDir()
	out := p.cache.TmpName(digest)

	var headers []string
	if auth != "" {
		headers = append(headers, "Authorization: "+auth)
	}
	var checksum string
	if alg == "sha256" {
		checksum = hexDigest
	}
	// No BasicCreds here: net/http already followed the registry -> CDN
	// redirect in fetchBlob and stripped Authorization if that crossed
	// hosts, so headers holds a bearer token that is valid for finalURL's
	// host specifically.
	if err := p.aria2.Download(ctx, finalURL, headers, nil, dir, out, p.cfg.Aria2Connections, p.cfg.Aria2MinSplit, checksum, nil); err != nil {
		return err
	}
	downloaded := filepath.Join(dir, out)
	if checksum == "" {
		// Non-sha256 digest: aria2 couldn't verify it for us, so stream-hash
		// the file ourselves rather than trusting the transfer blindly.
		if err := verifyFileStreaming(alg, hexDigest, downloaded); err != nil {
			os.Remove(downloaded)
			return err
		}
	}
	return p.cache.Commit(digest, downloaded)
}

func verifyDigest(alg, want string, data []byte) error {
	h, err := newHash(alg)
	if err != nil {
		return err
	}
	h.Write(data)
	got := hex.EncodeToString(h.Sum(nil))
	if got != want {
		return fmt.Errorf("digest mismatch: want %s:%s got %s:%s", alg, want, alg, got)
	}
	return nil
}

func verifyFileStreaming(alg, want, path string) error {
	h, err := newHash(alg)
	if err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != want {
		return fmt.Errorf("digest mismatch: want %s:%s got %s:%s", alg, want, alg, got)
	}
	return nil
}

func newHash(alg string) (hash.Hash, error) {
	switch alg {
	case "sha256":
		return sha256.New(), nil
	default:
		return nil, fmt.Errorf("unsupported digest algorithm %q", alg)
	}
}
