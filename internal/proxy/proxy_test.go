package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"registry-proxy/internal/aria2"
	"registry-proxy/internal/cache"
	"registry-proxy/internal/config"
)

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func hostPort(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parsing %q: %v", srv.URL, err)
	}
	return u.Host
}

// requireAria2DockerImage skips the test unless both docker and the aria2
// image aria2.Start runs are available, since building the image isn't
// something a plain `go test` run should require.
func requireAria2DockerImage(t *testing.T) {
	t.Helper()
	const dockerImage = "registry-proxy-aria2:local"
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not found in PATH")
	}
	if err := exec.Command("docker", "image", "inspect", dockerImage).Run(); err != nil {
		t.Skipf("%s not built, skipping (see docker/aria2)", dockerImage)
	}
}

func newTestProxy(t *testing.T, insecureHosts ...string) (*Proxy, *httptest.Server) {
	t.Helper()
	c, err := cache.New(t.TempDir())
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}
	cfg := &config.Config{
		HTTPTimeout:        5 * time.Second,
		MinAria2Size:       1 << 30, // default to "always direct-fetch" unless a test overrides it
		Aria2MinSplit:      "1M",
		InsecureRegistries: insecureHosts,
	}
	p := New(cfg, c, nil)
	srv := httptest.NewServer(p)
	t.Cleanup(srv.Close)
	return p, srv
}

func TestProxyPing(t *testing.T) {
	_, srv := newTestProxy(t)
	resp, err := http.Get(srv.URL + "/v2/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestProxyManifestPassthrough(t *testing.T) {
	const manifestBody = `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}`
	var gotAccept string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAccept = r.Header.Get("Accept")
		w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
		w.Header().Set("Docker-Content-Digest", "sha256:"+sha256Hex([]byte(manifestBody)))
		w.Write([]byte(manifestBody))
	}))
	defer upstream.Close()

	_, srv := newTestProxy(t, hostPort(t, upstream))

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v2/"+hostPort(t, upstream)+"/myrepo/manifests/latest", nil)
	req.Header.Set("Accept", "application/vnd.oci.image.manifest.v1+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != manifestBody {
		t.Errorf("body = %q, want %q", body, manifestBody)
	}
	if gotAccept != "application/vnd.oci.image.manifest.v1+json" {
		t.Errorf("upstream saw Accept=%q", gotAccept)
	}
	if resp.Header.Get("Docker-Content-Digest") == "" {
		t.Error("Docker-Content-Digest not forwarded")
	}
}

// blobUpstream stands in for a registry (redirects blob GET/HEAD to a
// separate storage server) plus the storage server itself, mimicking how
// Docker Hub and similar registries offload blobs to a CDN.
type blobUpstream struct {
	registry *httptest.Server
	storage  *httptest.Server
	digest   string
	hits     int32 // storage hits
}

func newBlobUpstream(t *testing.T, content []byte) *blobUpstream {
	t.Helper()
	b := &blobUpstream{digest: "sha256:" + sha256Hex(content)}

	b.storage = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&b.hits, 1)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(content)))
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write(content)
	}))
	t.Cleanup(b.storage.Close)

	b.registry = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, b.storage.URL+"/blob-data", http.StatusMovedPermanently)
	}))
	t.Cleanup(b.registry.Close)
	return b
}

func TestProxyBlobDirectFetchAndCache(t *testing.T) {
	content := []byte("small blob content, well under the aria2 threshold")
	up := newBlobUpstream(t, content)
	p, srv := newTestProxy(t, hostPort(t, up.registry))

	blobURL := srv.URL + "/v2/" + hostPort(t, up.registry) + "/x/blobs/" + up.digest
	resp, err := http.Get(blobURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if string(body) != string(content) {
		t.Errorf("body = %q, want %q", body, content)
	}
	if got := resp.Header.Get("Docker-Content-Digest"); got != up.digest {
		t.Errorf("Docker-Content-Digest = %q, want %q", got, up.digest)
	}
	if !p.cache.Has(up.digest) {
		t.Error("blob not committed to cache after fetch")
	}
}

func TestProxyBlobDigestMismatchRejected(t *testing.T) {
	realContent := []byte("this is the real content")
	wrongContent := []byte("this is NOT what the digest says")

	up := newBlobUpstream(t, realContent)
	// Point storage at content that doesn't match up.digest.
	up.storage.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(wrongContent)))
		if r.Method != http.MethodHead {
			w.Write(wrongContent)
		}
	})

	_, srv := newTestProxy(t, hostPort(t, up.registry))
	blobURL := srv.URL + "/v2/" + hostPort(t, up.registry) + "/x/blobs/" + up.digest
	resp, err := http.Get(blobURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502 on digest mismatch", resp.StatusCode)
	}
}

func TestProxyBlobHeadServedFromCacheWithoutUpstream(t *testing.T) {
	content := []byte("cached blob for HEAD test")
	up := newBlobUpstream(t, content)
	p, srv := newTestProxy(t, hostPort(t, up.registry))

	digestURL := srv.URL + "/v2/" + hostPort(t, up.registry) + "/x/blobs/" + up.digest
	if resp, err := http.Get(digestURL); err != nil {
		t.Fatal(err)
	} else {
		resp.Body.Close()
	}
	if !p.cache.Has(up.digest) {
		t.Fatal("precondition failed: blob should be cached")
	}

	// Kill the registry so any HEAD that actually reaches upstream fails loudly.
	up.registry.Close()

	resp, err := http.Head(digestURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HEAD status = %d, want 200 (served from cache)", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Length"); got != fmt.Sprintf("%d", len(content)) {
		t.Errorf("Content-Length = %q, want %d", got, len(content))
	}
}

func TestProxyBlobSingleflightDedupesConcurrentFetches(t *testing.T) {
	content := []byte("deduped concurrent blob fetch content")
	up := newBlobUpstream(t, content)
	_, srv := newTestProxy(t, hostPort(t, up.registry))

	blobURL := srv.URL + "/v2/" + hostPort(t, up.registry) + "/x/blobs/" + up.digest

	var wg sync.WaitGroup
	results := make([]string, 8)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp, err := http.Get(blobURL)
			if err != nil {
				t.Error(err)
				return
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			results[i] = string(body)
		}(i)
	}
	wg.Wait()

	for i, got := range results {
		if got != string(content) {
			t.Errorf("caller %d got %q, want %q", i, got, content)
		}
	}
	// The storage server (final hop) should only have been hit once for the
	// GET (plus once for the HEAD resolution before the singleflight'd fetch).
	if hits := atomic.LoadInt32(&up.hits); hits > 2 {
		t.Errorf("storage hit %d times, want at most 2 (one HEAD + one GET) despite %d concurrent callers", hits, len(results))
	}
}

func TestProxyBlobAria2Fetch(t *testing.T) {
	requireAria2DockerImage(t)

	// Large enough to be unambiguous, small enough to keep the test fast.
	content := make([]byte, 2*1024*1024)
	for i := range content {
		content[i] = byte(i % 251)
	}
	up := newBlobUpstream(t, content)

	cacheDir := t.TempDir()
	c, err := cache.New(cacheDir)
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}
	cfg := &config.Config{
		CacheDir:           cacheDir,
		HTTPTimeout:        5 * time.Second,
		MinAria2Size:       1024, // force the aria2 path
		Aria2RPCPort:       16880,
		Aria2Connections:   4,
		Aria2MinSplit:      "1M",
		InsecureRegistries: []string{hostPort(t, up.registry)},
	}
	a, err := aria2.Start(cfg)
	if err != nil {
		t.Fatalf("aria2.Start: %v", err)
	}
	t.Cleanup(a.Stop)

	p := New(cfg, c, a)
	srv := httptest.NewServer(p)
	t.Cleanup(srv.Close)

	blobURL := srv.URL + "/v2/" + hostPort(t, up.registry) + "/x/blobs/" + up.digest
	resp, err := http.Get(blobURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := sha256Hex(body); got != up.digest[len("sha256:"):] {
		t.Errorf("downloaded content digest mismatch: got sha256:%s want %s", got, up.digest)
	}
	if len(body) != len(content) {
		t.Errorf("downloaded %d bytes, want %d", len(body), len(content))
	}
}

func writeTestNetrc(t *testing.T, host, login, password string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "netrc")
	content := fmt.Sprintf("machine %s\nlogin %s\npassword %s\n", host, login, password)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestFetchGenericDirectSendsNetrcBasicAuth covers the /fetch?url=... path
// that doesn't go through aria2 (content under MinAria2Size): it should
// attach the Authorization header for a host with a netrc-path entry.
func TestFetchGenericDirectSendsNetrcBasicAuth(t *testing.T) {
	content := []byte("small enough to skip aria2")
	var gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(content)))
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Write(content)
	}))
	defer upstream.Close()

	host := hostPort(t, upstream)
	netrcPath := writeTestNetrc(t, strings.Split(host, ":")[0], "alice", "s3cret")

	c, err := cache.New(t.TempDir())
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}
	cfg := &config.Config{
		HTTPTimeout:  5 * time.Second,
		MinAria2Size: 1 << 30,
		NetrcPath:    netrcPath,
	}
	p := New(cfg, c, nil)
	srv := httptest.NewServer(p)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/fetch?url=" + url.QueryEscape(upstream.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	const want = "Basic YWxpY2U6czNjcmV0"
	if gotAuth != want {
		t.Errorf("upstream saw Authorization=%q, want %q", gotAuth, want)
	}
}

// TestFetchGenericDirectForwardsHeadersExceptHopByHop: the preflight HEAD's
// response headers should reach the client (e.g. ETag, Cache-Control - a
// strict client may validate on these, not just Content-Type), but
// connection-scoped headers must not be copied onto a different connection.
func TestFetchGenericDirectForwardsHeadersExceptHopByHop(t *testing.T) {
	content := []byte(`{"ok":true}`)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `"abc123"`)
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "close")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(content)))
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Write(content)
	}))
	defer upstream.Close()

	c, err := cache.New(t.TempDir())
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}
	cfg := &config.Config{
		HTTPTimeout:  5 * time.Second,
		MinAria2Size: 1 << 30,
	}
	p := New(cfg, c, nil)
	srv := httptest.NewServer(p)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/fetch?url=" + url.QueryEscape(upstream.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if string(body) != string(content) {
		t.Errorf("body = %q, want %q", body, content)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	if got := resp.Header.Get("ETag"); got != `"abc123"` {
		t.Errorf("ETag = %q, want \"abc123\"", got)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-cache" {
		t.Errorf("Cache-Control = %q, want no-cache", got)
	}
	if got := resp.Header.Get("Content-Length"); got != fmt.Sprintf("%d", len(content)) {
		t.Errorf("Content-Length = %q, want %d (the actual served body, not the HEAD's)", got, len(content))
	}
	if got := resp.Header.Get("Connection"); got != "" {
		t.Errorf("Connection = %q, want unset - hop-by-hop headers must not be forwarded", got)
	}
}

// TestFetchGenericCacheHitStillGetsRealContentType: a second request for a
// URL already cached from a prior fetch must still get the real
// Content-Type, not http.ServeContent's sniffing - a pure cache hit never
// calls fetchGeneric again, so without persisting the first fetch's headers
// (cache.WriteMeta/ReadMeta) every repeat request for a JSON body would
// come back as "text/plain; charset=utf-8" (Go's sniffer has no JSON
// signature), exactly the mismatch that broke Conan against the real
// Artifactory API in production.
func TestFetchGenericCacheHitStillGetsRealContentType(t *testing.T) {
	content := []byte(`{"ok":true}`)
	var upstreamHits int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			upstreamHits++
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(content)))
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Write(content)
	}))
	defer upstream.Close()

	c, err := cache.New(t.TempDir())
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}
	cfg := &config.Config{
		HTTPTimeout:  5 * time.Second,
		MinAria2Size: 1 << 30,
	}
	p := New(cfg, c, nil)
	srv := httptest.NewServer(p)
	defer srv.Close()

	fetchURL := srv.URL + "/fetch?url=" + url.QueryEscape(upstream.URL)
	for i := 0; i < 2; i++ {
		resp, err := http.Get(fetchURL)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200", i, resp.StatusCode)
		}
		if string(body) != string(content) {
			t.Errorf("request %d: body = %q, want %q", i, body, content)
		}
		if got := resp.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("request %d: Content-Type = %q, want application/json", i, got)
		}
	}
	if upstreamHits != 1 {
		t.Errorf("upstream GET hits = %d, want 1 (second request should be a pure cache hit)", upstreamHits)
	}
}

// TestFetchGenericAria2SendsNetrcBasicAuth: aria2-backed counterpart of
// TestFetchGenericDirectSendsNetrcBasicAuth; upstream must 401 first since
// http-user/http-passwd is challenge-based.
func TestFetchGenericAria2SendsNetrcBasicAuth(t *testing.T) {
	requireAria2DockerImage(t)

	content := make([]byte, 2*1024*1024)
	var gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodGet {
			gotAuth = auth
		}
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(content)))
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Write(content)
	}))
	defer upstream.Close()

	host := hostPort(t, upstream)
	netrcPath := writeTestNetrc(t, strings.Split(host, ":")[0], "bob", "topsecret")

	cacheDir := t.TempDir()
	c, err := cache.New(cacheDir)
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}
	cfg := &config.Config{
		CacheDir:         cacheDir,
		HTTPTimeout:      5 * time.Second,
		MinAria2Size:     1024,
		Aria2RPCPort:     16884,
		Aria2Connections: 4,
		Aria2MinSplit:    "1M",
		NetrcPath:        netrcPath,
	}
	a, err := aria2.Start(cfg)
	if err != nil {
		t.Fatalf("aria2.Start: %v", err)
	}
	t.Cleanup(a.Stop)

	p := New(cfg, c, a)
	srv := httptest.NewServer(p)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/fetch?url=" + url.QueryEscape(upstream.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if len(body) != len(content) {
		t.Errorf("downloaded %d bytes, want %d", len(body), len(content))
	}
	const want = "Basic Ym9iOnRvcHNlY3JldA=="
	if gotAuth != want {
		t.Errorf("upstream saw Authorization=%q, want %q", gotAuth, want)
	}
}

// TestFetchGenericAria2PreservesContentType: the early-200 path (fired from
// aria2's onStarted, see fetchURL) must still carry the upstream's
// Content-Type, picked up from the preflight HEAD in fetchGeneric - a client
// parsing the body (e.g. a pypi simple-index page) needs it to know what it
// got. The body is written in slow chunks so the download stays "active"
// for multiple aria2 poll ticks and onStarted actually fires, instead of
// completing within a single tick (see the "no onStarted" caveat in
// fetchURL's doc comment).
func TestFetchGenericAria2PreservesContentType(t *testing.T) {
	requireAria2DockerImage(t)

	content := make([]byte, 2*1024*1024)
	const wantType = "application/vnd.pypi.simple.v1+json"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", wantType)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(content)))
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		const chunk = 256 * 1024
		for i := 0; i < len(content); i += chunk {
			end := i + chunk
			if end > len(content) {
				end = len(content)
			}
			w.Write(content[i:end])
			if flusher != nil {
				flusher.Flush()
			}
			time.Sleep(150 * time.Millisecond)
		}
	}))
	defer upstream.Close()

	cacheDir := t.TempDir()
	c, err := cache.New(cacheDir)
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}
	cfg := &config.Config{
		CacheDir:         cacheDir,
		HTTPTimeout:      5 * time.Second,
		MinAria2Size:     1024,
		Aria2RPCPort:     16886,
		Aria2Connections: 4,
		Aria2MinSplit:    "1M",
	}
	a, err := aria2.Start(cfg)
	if err != nil {
		t.Fatalf("aria2.Start: %v", err)
	}
	t.Cleanup(a.Stop)

	p := New(cfg, c, a)
	srv := httptest.NewServer(p)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/fetch?url=" + url.QueryEscape(upstream.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != wantType {
		t.Errorf("Content-Type = %q, want %q", got, wantType)
	}
}

// TestFetchURL404FromUpstreamReturns404: a real 404 must surface as 404, not
// an early 200 fired before aria2.Download's onStarted gate fires.
func TestFetchURL404FromUpstreamReturns404(t *testing.T) {
	requireAria2DockerImage(t)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer upstream.Close()

	cacheDir := t.TempDir()
	c, err := cache.New(cacheDir)
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}
	cfg := &config.Config{
		CacheDir:         cacheDir,
		HTTPTimeout:      5 * time.Second,
		MinAria2Size:     1 << 30,
		Aria2RPCPort:     16885,
		Aria2Connections: 4,
		Aria2MinSplit:    "1M",
	}
	a, err := aria2.Start(cfg)
	if err != nil {
		t.Fatalf("aria2.Start: %v", err)
	}
	t.Cleanup(a.Stop)

	p := New(cfg, c, a)
	srv := httptest.NewServer(p)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/fetch?url=" + url.QueryEscape(upstream.URL+"/missing"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

// TestFetchGenericAria2AuthNotSentToRedirectTarget: Artifactory -> S3 shape;
// aria2 must not re-send Authorization to a redirect target that 400s on it
// (errorCode=22); see aria2.BasicCreds.
func TestFetchGenericAria2AuthNotSentToRedirectTarget(t *testing.T) {
	requireAria2DockerImage(t)

	content := make([]byte, 2*1024*1024)
	var redirectTargetSawAuth bool
	// storage stands in for S3; only aria2's GET is judged (both servers
	// share a hostname here, unlike production, so the HEAD preflight
	// isn't representative - its result only ever drives size, not auth).
	storage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.Header.Get("Authorization") != "" {
			redirectTargetSawAuth = true
			http.Error(w, "InvalidArgument: Only one auth mechanism allowed", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(content)))
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Write(content)
	}))
	defer storage.Close()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		http.Redirect(w, r, storage.URL+"/blob?X-Amz-Signature=deadbeef", http.StatusFound)
	}))
	defer upstream.Close()

	host := hostPort(t, upstream)
	netrcPath := writeTestNetrc(t, strings.Split(host, ":")[0], "bob", "topsecret")

	cacheDir := t.TempDir()
	c, err := cache.New(cacheDir)
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}
	cfg := &config.Config{
		CacheDir:         cacheDir,
		HTTPTimeout:      5 * time.Second,
		MinAria2Size:     1024,
		Aria2RPCPort:     16886,
		Aria2Connections: 4,
		Aria2MinSplit:    "1M",
		NetrcPath:        netrcPath,
	}
	a, err := aria2.Start(cfg)
	if err != nil {
		t.Fatalf("aria2.Start: %v", err)
	}
	t.Cleanup(a.Stop)

	p := New(cfg, c, a)
	srv := httptest.NewServer(p)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/fetch?url=" + url.QueryEscape(upstream.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if len(body) != len(content) {
		t.Errorf("downloaded %d bytes, want %d", len(body), len(content))
	}
	if redirectTargetSawAuth {
		t.Error("redirect target's GET carried an Authorization header; aria2 must not re-send it to a redirect target")
	}
}
