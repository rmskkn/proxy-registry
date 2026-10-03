package auth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestParseBearerChallenge(t *testing.T) {
	h := `Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/nginx:pull"`
	realm, service, scope, ok := parseBearerChallenge(h)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if realm != "https://auth.docker.io/token" || service != "registry.docker.io" || scope != "repository:library/nginx:pull" {
		t.Errorf("got realm=%q service=%q scope=%q", realm, service, scope)
	}

	if _, _, _, ok := parseBearerChallenge("Basic realm=foo"); ok {
		t.Error("non-Bearer challenge should not parse as ok")
	}
}

func TestAuthenticatorTokenCacheExpiry(t *testing.T) {
	a := New(&http.Client{})
	a.cacheToken("k", "v1", 50*time.Millisecond)
	if got, ok := a.cachedToken("k"); !ok || got != "v1" {
		t.Fatalf("expected fresh token, got %q ok=%v", got, ok)
	}
	time.Sleep(60 * time.Millisecond)
	if _, ok := a.cachedToken("k"); ok {
		t.Error("expected token to have expired")
	}
}

// TestAuthenticatorDoRoundTrip exercises the full 401 -> token fetch ->
// retry-with-bearer flow against two fake HTTP servers standing in for a
// registry and its auth server.
func TestAuthenticatorDoRoundTrip(t *testing.T) {
	var tokenRequests, authedRequests int

	var registry *httptest.Server
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenRequests++
		if r.URL.Query().Get("service") != "test-service" {
			t.Errorf("token request missing expected service param, got %q", r.URL.Query().Get("service"))
		}
		fmt.Fprint(w, `{"token":"test-token-123","expires_in":60}`)
	}))
	defer authServer.Close()

	registry = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer test-token-123" {
			authedRequests++
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s/token",service="test-service",scope="repository:x:pull"`, authServer.URL))
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer registry.Close()

	a := New(&http.Client{Timeout: 5 * time.Second})

	req, _ := http.NewRequest(http.MethodGet, registry.URL+"/v2/x/manifests/latest", nil)
	resp, err := a.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("final status = %d, want 200", resp.StatusCode)
	}
	if tokenRequests != 1 {
		t.Errorf("token server hit %d times, want 1", tokenRequests)
	}
	if authedRequests != 1 {
		t.Errorf("registry hit with valid bearer %d times, want 1", authedRequests)
	}

	// A second call should reuse the cached token and not hit the auth server again.
	req2, _ := http.NewRequest(http.MethodGet, registry.URL+"/v2/x/manifests/latest", nil)
	resp2, err := a.Do(req2)
	if err != nil {
		t.Fatalf("Do (2nd): %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Errorf("second call status = %d, want 200", resp2.StatusCode)
	}
	if tokenRequests != 1 {
		t.Errorf("token server hit %d times after 2nd call, want still 1 (cached)", tokenRequests)
	}
}
