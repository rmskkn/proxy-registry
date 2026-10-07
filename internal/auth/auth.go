// Package auth implements the Docker registry bearer-token auth challenge:
// detecting a 401 WWW-Authenticate challenge, fetching an (anonymous) token
// from the realm it names, and retrying the request with it attached.
package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type cachedToken struct {
	value   string
	expires time.Time
}

// Authenticator performs upstream requests against a Docker registry,
// transparently handling its bearer-token auth challenge and caching the
// resulting tokens. Only anonymous/public pulls are supported.
type Authenticator struct {
	Client *http.Client

	mu     sync.Mutex
	tokens map[string]cachedToken

	netrc map[string]credential
}

// New creates an Authenticator that issues requests via client.
func New(client *http.Client) *Authenticator {
	return &Authenticator{Client: client, tokens: make(map[string]cachedToken)}
}

// LoadNetrc reads netrc-format credentials from path for use by BasicAuth.
func (a *Authenticator) LoadNetrc(path string) error {
	creds, err := parseNetrc(path)
	if err != nil {
		return err
	}
	a.netrc = creds
	return nil
}

// BasicAuth returns an HTTP "Authorization" header value for host, from
// credentials loaded via LoadNetrc, if host has an entry.
func (a *Authenticator) BasicAuth(host string) (string, bool) {
	login, password, ok := a.BasicCreds(host)
	if !ok {
		return "", false
	}
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(login+":"+password)), true
}

// BasicCreds returns the login and password loaded for host via LoadNetrc,
// if host has an entry. Callers that hand credentials to something which
// does its own HTTP - aria2, via its http-user/http-passwd options - need
// them unencoded, rather than the pre-built header BasicAuth returns.
func (a *Authenticator) BasicCreds(host string) (login, password string, ok bool) {
	c, ok := a.netrc[host]
	if !ok {
		return "", "", false
	}
	return c.login, c.password, true
}

func (a *Authenticator) cachedToken(key string) (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	t, ok := a.tokens[key]
	if !ok || time.Now().After(t.expires) {
		return "", false
	}
	return t.value, true
}

func (a *Authenticator) cacheToken(key, value string, ttl time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.tokens[key] = cachedToken{value: value, expires: time.Now().Add(ttl)}
}

// parseBearerChallenge parses a `WWW-Authenticate: Bearer realm="...",service="...",scope="..."` header.
func parseBearerChallenge(h string) (realm, service, scope string, ok bool) {
	if !strings.HasPrefix(h, "Bearer ") {
		return "", "", "", false
	}
	for _, part := range strings.Split(strings.TrimPrefix(h, "Bearer "), ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		v := strings.Trim(kv[1], `"`)
		switch kv[0] {
		case "realm":
			realm = v
		case "service":
			service = v
		case "scope":
			scope = v
		}
	}
	return realm, service, scope, realm != ""
}

// token fetches (or reuses a cached) bearer token satisfying a registry's
// auth challenge.
func (a *Authenticator) token(realm, service, scope string) (string, error) {
	key := realm + "|" + service + "|" + scope
	if tok, ok := a.cachedToken(key); ok {
		return tok, nil
	}
	u, err := url.Parse(realm)
	if err != nil {
		return "", err
	}
	q := u.Query()
	if service != "" {
		q.Set("service", service)
	}
	if scope != "" {
		q.Set("scope", scope)
	}
	u.RawQuery = q.Encode()

	resp, err := a.Client.Get(u.String())
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token request to %s failed: %s", realm, resp.Status)
	}
	var body struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", err
	}
	tok := body.Token
	if tok == "" {
		tok = body.AccessToken
	}
	if tok == "" {
		return "", fmt.Errorf("token response from %s had no token", realm)
	}
	ttl := time.Duration(body.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	a.cacheToken(key, tok, ttl)
	return tok, nil
}

// Do performs req against the upstream, transparently handling the Docker
// registry token-auth challenge: on a 401 with a Bearer challenge, it fetches
// a token and retries once with a fresh request built from req's method,
// URL, and headers (req itself may already have been consumed by the first
// attempt, so it is never reused directly).
func (a *Authenticator) Do(req *http.Request) (*http.Response, error) {
	resp, err := a.Client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}
	challenge := resp.Header.Get("WWW-Authenticate")
	resp.Body.Close()
	realm, service, scope, ok := parseBearerChallenge(challenge)
	if !ok {
		return resp, nil
	}
	tok, err := a.token(realm, service, scope)
	if err != nil {
		return nil, fmt.Errorf("token auth: %w", err)
	}
	retry, err := http.NewRequest(req.Method, req.URL.String(), nil)
	if err != nil {
		return nil, err
	}
	retry.Header = req.Header.Clone()
	retry.Header.Set("Authorization", "Bearer "+tok)
	return a.Client.Do(retry)
}
