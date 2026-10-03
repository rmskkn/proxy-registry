package registry

import (
	"testing"

	"registry-proxy/internal/config"
)

func TestLooksLikeHost(t *testing.T) {
	cases := map[string]bool{
		"docker.io":        true,
		"gcr.io":           true,
		"ghcr.io":          true,
		"localhost":        true,
		"localhost:5000":   true,
		"my.registry:5000": true,
		"nginx":            false,
		"library":          false,
		"foo":              false,
	}
	for in, want := range cases {
		if got := looksLikeHost(in); got != want {
			t.Errorf("looksLikeHost(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestResolveUpstream(t *testing.T) {
	cases := []struct {
		name     string
		wantHost string
		wantRepo string
	}{
		{"nginx", "registry-1.docker.io", "library/nginx"},
		{"library/nginx", "registry-1.docker.io", "library/nginx"},
		{"someuser/someimage", "registry-1.docker.io", "someuser/someimage"},
		{"docker.io/library/nginx", "registry-1.docker.io", "library/nginx"},
		{"index.docker.io/library/nginx", "registry-1.docker.io", "library/nginx"},
		{"gcr.io/google-containers/pause", "gcr.io", "google-containers/pause"},
		{"ghcr.io/foo/bar", "ghcr.io", "foo/bar"},
		{"registry.k8s.io/pause", "registry.k8s.io", "pause"},
		{"localhost:5000/foo/bar", "localhost:5000", "foo/bar"},
		{"localhost/foo", "localhost", "foo"},
		{"my.private.registry:5000/ns/app", "my.private.registry:5000", "ns/app"},
	}
	for _, c := range cases {
		host, repo := ResolveUpstream(c.name)
		if host != c.wantHost || repo != c.wantRepo {
			t.Errorf("ResolveUpstream(%q) = (%q, %q), want (%q, %q)", c.name, host, repo, c.wantHost, c.wantRepo)
		}
	}
}

func TestUpstreamScheme(t *testing.T) {
	cfg := &config.Config{InsecureRegistries: []string{"my.registry:5000", "plain.local"}}
	cases := map[string]string{
		"my.registry:5000":     "http",
		"plain.local":          "http",
		"registry-1.docker.io": "https",
		"gcr.io":               "https",
	}
	for host, want := range cases {
		if got := UpstreamScheme(cfg, host); got != want {
			t.Errorf("UpstreamScheme(%q) = %q, want %q", host, got, want)
		}
	}

	wildcard := &config.Config{InsecureRegistries: []string{"*"}}
	if got := UpstreamScheme(wildcard, "anything.example"); got != "http" {
		t.Errorf("wildcard insecure-registries: got %q, want http", got)
	}
}

func TestParseV2Path(t *testing.T) {
	cases := []struct {
		path     string
		wantKind string
		wantName string
		wantArg  string
	}{
		{"/v2/nginx/manifests/latest", "manifest", "nginx", "latest"},
		{"/v2/library/nginx/manifests/sha256:abc", "manifest", "library/nginx", "sha256:abc"},
		{"/v2/gcr.io/foo/bar/blobs/sha256:deadbeef", "blob", "gcr.io/foo/bar", "sha256:deadbeef"},
		{"/v2/nginx/tags/list", "tags", "nginx", ""},
	}
	for _, c := range cases {
		req, err := ParseV2Path(c.path)
		if err != nil {
			t.Fatalf("ParseV2Path(%q): unexpected error: %v", c.path, err)
		}
		if req.Kind != c.wantKind || req.Name != c.wantName || req.Arg != c.wantArg {
			t.Errorf("ParseV2Path(%q) = %+v, want kind=%q name=%q arg=%q", c.path, req, c.wantKind, c.wantName, c.wantArg)
		}
	}

	if _, err := ParseV2Path("/v2/nginx/uploads/"); err == nil {
		t.Error("expected error for unrecognized route, got nil")
	}
}
