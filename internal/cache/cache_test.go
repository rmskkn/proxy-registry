package cache

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// hex64 builds a syntactically valid 64-char hex-ish digest body for tests
// that don't care about the actual hash value, only that it round-trips.
func hex64(b byte) string { return strings.Repeat(string([]byte{b}), 64) }

func TestSplitDigest(t *testing.T) {
	alg, hex, ok := SplitDigest("sha256:abcd")
	if !ok || alg != "sha256" || hex != "abcd" {
		t.Errorf("SplitDigest(sha256:abcd) = (%q, %q, %v)", alg, hex, ok)
	}
	for _, bad := range []string{"", "sha256", "sha256:", ":abcd", "sha256:a"} {
		if _, _, ok := SplitDigest(bad); ok {
			t.Errorf("SplitDigest(%q) should fail", bad)
		}
	}
}

func TestCacheWriteHasOpenStat(t *testing.T) {
	c, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	digest := "sha256:" + hex64('a')
	data := []byte("hello world")

	if c.Has(digest) {
		t.Fatal("blob reported cached before being written")
	}

	if err := c.Write(digest, data); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !c.Has(digest) {
		t.Fatal("blob not reported cached after Write")
	}

	fi, err := c.Stat(digest)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if fi.Size() != int64(len(data)) {
		t.Errorf("Stat size = %d, want %d", fi.Size(), len(data))
	}

	f, fi2, err := c.Open(digest)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close()
	if fi2.Size() != int64(len(data)) {
		t.Errorf("Open size = %d, want %d", fi2.Size(), len(data))
	}
}

func TestCacheCommit(t *testing.T) {
	c, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	digest := "sha256:" + hex64('1')

	tmp := filepath.Join(c.TmpDir(), c.TmpName(digest))
	if err := os.WriteFile(tmp, []byte("payload"), 0o644); err != nil {
		t.Fatalf("writing tmp file: %v", err)
	}
	if err := c.Commit(digest, tmp); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if !c.Has(digest) {
		t.Fatal("blob not present after Commit")
	}
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Error("tmp file should have been moved (renamed), not copied")
	}
}

func TestCacheInvalidDigestRejected(t *testing.T) {
	c, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.Has("not-a-digest") {
		t.Error("Has should report false for a malformed digest")
	}
	if err := c.Write("not-a-digest", []byte("x")); err == nil {
		t.Error("Write should reject a malformed digest")
	}
}
