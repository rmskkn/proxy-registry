package auth

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func writeNetrc(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "netrc")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseNetrcSingleMachine(t *testing.T) {
	path := writeNetrc(t, "machine example.com login alice password s3cret\n")
	creds, err := parseNetrc(path)
	if err != nil {
		t.Fatalf("parseNetrc: %v", err)
	}
	c, ok := creds["example.com"]
	if !ok {
		t.Fatal("example.com not found")
	}
	if c.login != "alice" || c.password != "s3cret" {
		t.Errorf("got login=%q password=%q, want alice/s3cret", c.login, c.password)
	}
}

func TestParseNetrcMultipleMachines(t *testing.T) {
	path := writeNetrc(t, `
machine one.example.com
login u1
password p1
machine two.example.com
login u2
password p2
`)
	creds, err := parseNetrc(path)
	if err != nil {
		t.Fatalf("parseNetrc: %v", err)
	}
	if len(creds) != 2 {
		t.Fatalf("got %d entries, want 2", len(creds))
	}
	if creds["one.example.com"].login != "u1" || creds["two.example.com"].login != "u2" {
		t.Errorf("got %+v", creds)
	}
}

func TestParseNetrcMissingFile(t *testing.T) {
	if _, err := parseNetrc(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Error("expected error for missing file")
	}
}

func TestParseNetrcTruncatedTokenRejected(t *testing.T) {
	cases := []string{
		"machine",
		"machine example.com login",
		"machine example.com login alice password",
	}
	for _, content := range cases {
		path := writeNetrc(t, content)
		if _, err := parseNetrc(path); err == nil {
			t.Errorf("parseNetrc(%q) expected error, got nil", content)
		}
	}
}

func TestAuthenticatorBasicAuthFromNetrc(t *testing.T) {
	path := writeNetrc(t, "machine example.com login alice password s3cret\n")
	a := New(&http.Client{})
	if err := a.LoadNetrc(path); err != nil {
		t.Fatalf("LoadNetrc: %v", err)
	}

	hdr, ok := a.BasicAuth("example.com")
	if !ok {
		t.Fatal("expected a match for example.com")
	}
	const want = "Basic YWxpY2U6czNjcmV0"
	if hdr != want {
		t.Errorf("BasicAuth = %q, want %q", hdr, want)
	}

	if _, ok := a.BasicAuth("other.example.com"); ok {
		t.Error("expected no match for other.example.com")
	}
}

func TestAuthenticatorBasicAuthWithoutLoadNetrc(t *testing.T) {
	a := New(&http.Client{})
	if _, ok := a.BasicAuth("example.com"); ok {
		t.Error("expected no match when LoadNetrc was never called")
	}
}
