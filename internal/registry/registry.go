// Package registry resolves client-facing repo names into an upstream
// registry host, repo path, and scheme, and recognizes the pull-relevant
// subset of the Docker Registry HTTP API v2 routes.
package registry

import (
	"fmt"
	"regexp"
	"strings"

	"registry-proxy/internal/config"
)

// hostAliases maps friendly names to the host that actually serves the
// Registry HTTP API v2. docker.io itself does not speak the registry
// protocol; registry-1.docker.io does.
var hostAliases = map[string]string{
	"docker.io":       "registry-1.docker.io",
	"index.docker.io": "registry-1.docker.io",
}

var (
	manifestRe = regexp.MustCompile(`^(.+)/manifests/([^/]+)$`)
	blobsRe    = regexp.MustCompile(`^(.+)/blobs/([^/]+)$`)
	tagsRe     = regexp.MustCompile(`^(.+)/tags/list$`)
)

// APIRequest is a parsed Docker Registry HTTP API v2 request.
type APIRequest struct {
	Kind string // "manifest", "blob", "tags"
	Name string // repo name as sent by the client, before upstream resolution
	Arg  string // reference, digest, or "" for tags
}

// ParseV2Path recognizes the pull-relevant subset of the Docker Registry
// HTTP API v2 routes under /v2/.
func ParseV2Path(p string) (*APIRequest, error) {
	p = strings.TrimPrefix(p, "/")
	p = strings.TrimPrefix(p, "v2/")
	if m := manifestRe.FindStringSubmatch(p); m != nil {
		return &APIRequest{Kind: "manifest", Name: m[1], Arg: m[2]}, nil
	}
	if m := blobsRe.FindStringSubmatch(p); m != nil {
		return &APIRequest{Kind: "blob", Name: m[1], Arg: m[2]}, nil
	}
	if m := tagsRe.FindStringSubmatch(p); m != nil {
		return &APIRequest{Kind: "tags", Name: m[1]}, nil
	}
	return nil, fmt.Errorf("unrecognized registry API path: %s", p)
}

// looksLikeHost reports whether a repo-name's first path segment should be
// treated as an upstream registry host, mirroring how the docker CLI itself
// decides whether an image reference's first component names a registry.
func looksLikeHost(seg string) bool {
	if seg == "localhost" {
		return true
	}
	return strings.ContainsAny(seg, ".:")
}

// ResolveUpstream splits a client-supplied repo name into the upstream
// registry host and the repo name to send to that host. This is what makes
// the proxy "universal": any registry can be addressed by embedding its host
// as the leading path component, e.g. pulling
// "proxy.local/gcr.io/google-containers/pause" resolves to
// gcr.io/v2/google-containers/pause/..., while a bare
// "proxy.local/nginx" resolves to docker.io/v2/library/nginx/...,
// matching Docker Hub's own implicit "library/" and default-registry rules.
func ResolveUpstream(name string) (host, repo string) {
	parts := strings.SplitN(name, "/", 2)
	if len(parts) == 2 && looksLikeHost(parts[0]) {
		host = parts[0]
		repo = parts[1]
	} else {
		host = "docker.io"
		repo = name
		if !strings.Contains(repo, "/") {
			repo = "library/" + repo
		}
	}
	if alias, ok := hostAliases[host]; ok {
		host = alias
	}
	return host, repo
}

// UpstreamScheme picks "http" or "https" for an upstream host, per
// cfg.InsecureRegistries. Matching is by exact host, or host:port.
func UpstreamScheme(cfg *config.Config, host string) string {
	for _, h := range cfg.InsecureRegistries {
		if h == "*" || h == host {
			return "http"
		}
	}
	return "https"
}
