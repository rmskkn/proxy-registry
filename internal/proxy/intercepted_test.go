package proxy

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"registry-proxy/internal/cache"
	"registry-proxy/internal/config"
)

// The intercepted path is what a client uses when it believes it is talking
// to the upstream itself: the upstream's hostname is pointed at this proxy
// out-of-band (/etc/hosts plus an iptables REDIRECT) and the proxy
// reconstructs the URL from the request. These tests drive
// serveIntercepted directly - ServeMITM is a one-line wrapper that only
// fixes the scheme - and reach the stub upstream through Proxy.dial, which
// stands in for the real-nameserver lookup dialBypassingHosts does in
// production.

const (
	interceptedHost  = "registry.test"
	interceptedRepo  = "team/app"
	interceptedTag   = "1.2.3"
	interceptedUser  = "alice"
	interceptedPass  = "s3cret"
	upstreamToken    = "test-bearer-token"
	mediaManifestV2  = "application/vnd.docker.distribution.manifest.v2+json"
	mediaManifestIdx = "application/vnd.docker.distribution.manifest.list.v2+json"
	mediaManifestV1  = "application/vnd.docker.distribution.manifest.v1+prettyjws"
	mediaOCIIndex    = "application/vnd.oci.image.index.v1+json"
)

// interceptedUpstream is a stub private registry shaped like Artifactory:
// every API request needs a bearer token, and the token endpoint itself
// refuses an anonymous request - the credentials have to come from netrc.
type interceptedUpstream struct {
	srv *httptest.Server

	manifestV2  []byte
	manifestIdx []byte
	manifestV1  []byte
	blob        []byte
	blobDigest  string

	mu           sync.Mutex
	tokenAuth    []string
	manifestHits int
	blobHits     int
}

func newInterceptedUpstream(t *testing.T) *interceptedUpstream {
	t.Helper()
	u := &interceptedUpstream{
		manifestV2:  []byte(`{"schemaVersion":2,"mediaType":"` + mediaManifestV2 + `","config":{}}`),
		manifestIdx: []byte(`{"schemaVersion":2,"mediaType":"` + mediaManifestIdx + `","manifests":[]}`),
		manifestV1:  []byte(`{"schemaVersion":1,"name":"` + interceptedRepo + `","fsLayers":[]}`),
		blob:        []byte("blob bytes served over the intercepted path"),
	}
	u.blobDigest = "sha256:" + sha256Hex(u.blob)

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("Authorization")
		u.mu.Lock()
		u.tokenAuth = append(u.tokenAuth, got)
		u.mu.Unlock()
		if !strings.HasPrefix(got, "Basic ") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"token":%q,"expires_in":60}`, upstreamToken)
	})
	mux.HandleFunc("/v2/"+interceptedRepo+"/manifests/", func(w http.ResponseWriter, r *http.Request) {
		if !u.authorized(w, r) {
			return
		}
		u.mu.Lock()
		u.manifestHits++
		u.mu.Unlock()
		// Mirrors registry:2: a client whose Accept names no schema-2 type
		// gets the manifest rewritten into schema 1 "to support old client",
		// under a digest that then does not exist in the registry.
		accept := strings.Join(r.Header.Values("Accept"), ", ")
		var body []byte
		var mediaType string
		switch {
		case strings.Contains(accept, mediaManifestIdx):
			body, mediaType = u.manifestIdx, mediaManifestIdx
		case strings.Contains(accept, mediaManifestV2):
			body, mediaType = u.manifestV2, mediaManifestV2
		default:
			body, mediaType = u.manifestV1, mediaManifestV1
		}
		w.Header().Set("Content-Type", mediaType)
		w.Header().Set("Docker-Content-Digest", "sha256:"+sha256Hex(body))
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Write(body)
	})
	mux.HandleFunc("/v2/"+interceptedRepo+"/blobs/", func(w http.ResponseWriter, r *http.Request) {
		if !u.authorized(w, r) {
			return
		}
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(u.blob)))
		if r.Method == http.MethodHead {
			// Not counted: fetchBlob preflights every download with a HEAD,
			// so only a body transfer tells a cache hit from a cache miss.
			w.WriteHeader(http.StatusOK)
			return
		}
		u.mu.Lock()
		u.blobHits++
		u.mu.Unlock()
		w.Write(u.blob)
	})

	u.srv = httptest.NewServer(mux)
	t.Cleanup(u.srv.Close)
	return u
}

// authorized answers an unauthenticated request with the bearer challenge a
// real registry sends, naming a realm on its own (intercepted) hostname so
// the token request has to travel through Proxy.dial as well.
func (u *interceptedUpstream) authorized(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("Authorization") == "Bearer "+upstreamToken {
		return true
	}
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(
		`Bearer realm="http://%s/token",service=%q,scope="repository:%s:pull"`,
		interceptedHost, interceptedHost, interceptedRepo))
	w.WriteHeader(http.StatusUnauthorized)
	return false
}

func (u *interceptedUpstream) counts() (manifests, blobs int) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.manifestHits, u.blobHits
}

func (u *interceptedUpstream) tokenRequests() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.tokenAuth...)
}

// stubResolver is Proxy.dial for these tests: it sends interceptedHost to
// the stub upstream and records every address asked for, so a request that
// went back to the proxy itself - the recursion that a hosts-respecting
// client caused - fails loudly instead of running until the client gives up.
type stubResolver struct {
	proxyAddr    string
	upstreamAddr string

	mu        sync.Mutex
	dialed    []string
	selfDials int
}

func (s *stubResolver) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.dialed = append(s.dialed, addr)
	isSelf := addr == s.proxyAddr
	if isSelf {
		s.selfDials++
	}
	s.mu.Unlock()
	if isSelf {
		return nil, fmt.Errorf("proxy dialed itself at %s", addr)
	}
	if host != interceptedHost {
		return nil, fmt.Errorf("unexpected dial to %s", addr)
	}
	return (&net.Dialer{}).DialContext(ctx, network, s.upstreamAddr)
}

func (s *stubResolver) stats() (dialed []string, selfDials int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.dialed...), s.selfDials
}

func newInterceptedProxy(t *testing.T, up *interceptedUpstream) (*Proxy, *httptest.Server, *stubResolver) {
	t.Helper()
	c, err := cache.New(t.TempDir())
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}
	cfg := &config.Config{
		HTTPTimeout:   5 * time.Second,
		MinAria2Size:  1 << 30, // keep every fetch on the direct path; aria2 is covered elsewhere
		Aria2MinSplit: "1M",
		MITM:          true,
		NetrcPath:     writeTestNetrc(t, interceptedHost, interceptedUser, interceptedPass),
	}
	p := New(cfg, c, nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.serveIntercepted(w, r, "http")
	}))
	t.Cleanup(srv.Close)

	resolver := &stubResolver{proxyAddr: hostPort(t, srv), upstreamAddr: hostPort(t, up.srv)}
	p.dial = resolver.dial
	return p, srv, resolver
}

// interceptedRequest issues one request at the proxy as the client sees it:
// the proxy's address, the upstream's hostname in the Host header.
func interceptedRequest(t *testing.T, srv *httptest.Server, method, path, accept string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = interceptedHost
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func manifestPath() string {
	return "/v2/" + interceptedRepo + "/manifests/" + interceptedTag
}

// TestInterceptedManifestHeadForwardsUpstreamStatus covers the HEAD docker
// sends before a pull. Served from the generic by-URL pipeline it reported
// a cache-cold 404 (or, once it probed the upstream through a
// hosts-respecting client, recursed into the proxy itself); it has to come
// from the upstream's own answer.
func TestInterceptedManifestHeadForwardsUpstreamStatus(t *testing.T) {
	up := newInterceptedUpstream(t)
	_, srv, _ := newInterceptedProxy(t, up)

	resp := interceptedRequest(t, srv, http.MethodHead, manifestPath(), mediaManifestV2)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got, want := resp.Header.Get("Docker-Content-Digest"), "sha256:"+sha256Hex(up.manifestV2); got != want {
		t.Errorf("Docker-Content-Digest = %q, want %q", got, want)
	}
	if got := resp.Header.Get("Content-Type"); got != mediaManifestV2 {
		t.Errorf("Content-Type = %q, want %q", got, mediaManifestV2)
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) != 0 {
		t.Errorf("HEAD returned a %d-byte body", len(body))
	}
	if manifests, _ := up.counts(); manifests != 1 {
		t.Errorf("upstream manifest hits = %d, want 1", manifests)
	}
}

// TestInterceptedManifestNotCachedAndVariesWithAccept pins the reason a
// manifest must not go through the by-URL cache: the key is the URL alone,
// while the body a registry returns depends on the client's Accept, so two
// clients pulling the same tag would get each other's media type.
func TestInterceptedManifestNotCachedAndVariesWithAccept(t *testing.T) {
	up := newInterceptedUpstream(t)
	_, srv, _ := newInterceptedProxy(t, up)

	v2 := interceptedRequest(t, srv, http.MethodGet, manifestPath(), mediaManifestV2)
	v2Body, _ := io.ReadAll(v2.Body)
	if v2.Header.Get("Content-Type") != mediaManifestV2 {
		t.Errorf("first Content-Type = %q, want %q", v2.Header.Get("Content-Type"), mediaManifestV2)
	}
	if string(v2Body) != string(up.manifestV2) {
		t.Errorf("first body = %q, want %q", v2Body, up.manifestV2)
	}

	idx := interceptedRequest(t, srv, http.MethodGet, manifestPath(), mediaManifestIdx)
	idxBody, _ := io.ReadAll(idx.Body)
	if idx.Header.Get("Content-Type") != mediaManifestIdx {
		t.Errorf("second Content-Type = %q, want %q", idx.Header.Get("Content-Type"), mediaManifestIdx)
	}
	if string(idxBody) != string(up.manifestIdx) {
		t.Errorf("second body = %q, want %q", idxBody, up.manifestIdx)
	}

	if manifests, _ := up.counts(); manifests != 2 {
		t.Errorf("upstream manifest hits = %d, want 2 (a manifest must not be cached)", manifests)
	}
}

// TestInterceptedManifestForwardsEveryAcceptHeader covers how docker states
// the manifest types it understands: several separate Accept header lines,
// not one list. Forwarding only the first (what Header.Get returns) left
// this registry believing the client understood nothing newer than schema 1,
// so it rewrote the manifest - and the digest it then advertised did not
// exist, which is what broke a real pull.
func TestInterceptedManifestForwardsEveryAcceptHeader(t *testing.T) {
	up := newInterceptedUpstream(t)
	_, srv, _ := newInterceptedProxy(t, up)

	req, err := http.NewRequest(http.MethodGet, srv.URL+manifestPath(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = interceptedHost
	// Order matters: the type this registry does not serve comes first.
	req.Header.Add("Accept", mediaOCIIndex)
	req.Header.Add("Accept", mediaManifestV2)

	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", manifestPath(), err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("Content-Type"); got != mediaManifestV2 {
		t.Errorf("Content-Type = %q, want %q (upstream saw a truncated Accept)", got, mediaManifestV2)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != string(up.manifestV2) {
		t.Errorf("body = %q, want %q", body, up.manifestV2)
	}
}

// TestInterceptedBlobUsesDigestCache checks that an intercepted blob lands
// in the digest-keyed cache the registry path owns, rather than a second
// copy keyed by its URL, and is served from there on the next request.
func TestInterceptedBlobUsesDigestCache(t *testing.T) {
	up := newInterceptedUpstream(t)
	p, srv, _ := newInterceptedProxy(t, up)
	blobPath := "/v2/" + interceptedRepo + "/blobs/" + up.blobDigest

	for i := 0; i < 2; i++ {
		resp := interceptedRequest(t, srv, http.MethodGet, blobPath, "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200", i+1, resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		if string(body) != string(up.blob) {
			t.Fatalf("request %d: body = %q, want %q", i+1, body, up.blob)
		}
	}
	if !p.cache.Has(up.blobDigest) {
		t.Errorf("blob not cached under its digest %s", up.blobDigest)
	}
	if _, blobs := up.counts(); blobs != 1 {
		t.Errorf("upstream blob hits = %d, want 1 (second request should be a cache hit)", blobs)
	}
}

// TestInterceptedTokenRequestSendsNetrcBasicAuth covers the private-registry
// case: the bearer-token endpoint authenticates the token request itself, so
// an anonymous one gets a 401 that surfaces as a 502 to the client.
func TestInterceptedTokenRequestSendsNetrcBasicAuth(t *testing.T) {
	up := newInterceptedUpstream(t)
	_, srv, _ := newInterceptedProxy(t, up)

	resp := interceptedRequest(t, srv, http.MethodGet, manifestPath(), mediaManifestV2)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d (%s), want 200", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(interceptedUser+":"+interceptedPass))
	requests := up.tokenRequests()
	if len(requests) == 0 {
		t.Fatal("token endpoint was never called")
	}
	for i, got := range requests {
		if got != want {
			t.Errorf("token request %d sent Authorization %q, want %q", i+1, got, want)
		}
	}
}

// TestInterceptedRequestsNeverDialTheProxyItself is the regression test for
// the recursion: for a host redirected here, an upstream request issued
// through a hosts-respecting client arrives back at this proxy, which
// issues it again. Every client the proxy owns must dial through p.dial,
// which resolves against the real nameserver instead.
func TestInterceptedRequestsNeverDialTheProxyItself(t *testing.T) {
	up := newInterceptedUpstream(t)
	_, srv, resolver := newInterceptedProxy(t, up)

	if resp := interceptedRequest(t, srv, http.MethodHead, manifestPath(), mediaManifestV2); resp.StatusCode != http.StatusOK {
		t.Fatalf("manifest HEAD status = %d, want 200", resp.StatusCode)
	}
	if resp := interceptedRequest(t, srv, http.MethodGet, manifestPath(), mediaManifestV2); resp.StatusCode != http.StatusOK {
		t.Fatalf("manifest GET status = %d, want 200", resp.StatusCode)
	}
	blobPath := "/v2/" + interceptedRepo + "/blobs/" + up.blobDigest
	if resp := interceptedRequest(t, srv, http.MethodGet, blobPath, ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("blob GET status = %d, want 200", resp.StatusCode)
	}

	dialed, selfDials := resolver.stats()
	if selfDials != 0 {
		t.Errorf("proxy dialed itself %d times", selfDials)
	}
	if len(dialed) == 0 {
		t.Fatal("no upstream dial went through p.dial")
	}
	for _, addr := range dialed {
		if host, _, _ := net.SplitHostPort(addr); host != interceptedHost {
			t.Errorf("dialed %q, want only %s", addr, interceptedHost)
		}
	}
}
