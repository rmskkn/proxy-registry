// Package cache is a content-addressed store for registry blobs, keyed by
// their digest (e.g. "sha256:abcd..."). Because digests are content hashes,
// a single cache entry is valid for every repo and every upstream registry
// that happens to share the same layer or config blob.
package cache

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Cache is a content-addressed blob store rooted at a directory on disk.
type Cache struct {
	dir string
}

// New creates (if needed) and opens a content-addressed cache at dir.
func New(dir string) (*Cache, error) {
	if err := os.MkdirAll(filepath.Join(dir, "blobs"), 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(dir, "tmp"), 0o755); err != nil {
		return nil, err
	}
	return &Cache{dir: dir}, nil
}

// SplitDigest splits a digest like "sha256:abcd..." into its algorithm and
// hex-encoded hash.
func SplitDigest(d string) (alg, hex string, ok bool) {
	parts := strings.SplitN(d, ":", 2)
	if len(parts) != 2 || parts[0] == "" || len(parts[1]) < 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// relPath returns a digest's location relative to the cache's blobs root,
// fanned out by the first two hex characters to avoid huge flat directories.
func relPath(digest string) (string, error) {
	alg, hex, ok := SplitDigest(digest)
	if !ok {
		return "", fmt.Errorf("invalid digest %q", digest)
	}
	return filepath.Join(alg, hex[:2], hex), nil
}

func (c *Cache) path(digest string) (string, error) {
	rel, err := relPath(digest)
	if err != nil {
		return "", err
	}
	return filepath.Join(c.dir, "blobs", rel), nil
}

// Has reports whether digest is already cached.
func (c *Cache) Has(digest string) bool {
	p, err := c.path(digest)
	if err != nil {
		return false
	}
	_, err = os.Stat(p)
	return err == nil
}

// Stat returns file info for a cached digest.
func (c *Cache) Stat(digest string) (os.FileInfo, error) {
	p, err := c.path(digest)
	if err != nil {
		return nil, err
	}
	return os.Stat(p)
}

// Open opens a cached digest for reading.
func (c *Cache) Open(digest string) (*os.File, os.FileInfo, error) {
	p, err := c.path(digest)
	if err != nil {
		return nil, nil, err
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, fi, nil
}

// TmpDir is the scratch directory in-progress downloads should land in
// before being committed into the cache.
func (c *Cache) TmpDir() string { return filepath.Join(c.dir, "tmp") }

// TmpName returns a scratch filename for a digest's in-progress download.
func (c *Cache) TmpName(digest string) string {
	_, hex, _ := SplitDigest(digest)
	return hex + ".part"
}

// Commit atomically moves a verified download into the content-addressed cache.
func (c *Cache) Commit(digest, tmpPath string) error {
	p, err := c.path(digest)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.Rename(tmpPath, p)
}

// Write commits an already-verified, in-memory blob (used for the
// small-blob direct-fetch path, which never touches aria2 or disk tmp files).
func (c *Cache) Write(digest string, data []byte) error {
	p, err := c.path(digest)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// metaPath is the sidecar path for a key's extra metadata (e.g. the
// upstream response headers learned when the entry was fetched).
func (c *Cache) metaPath(key string) (string, error) {
	p, err := c.path(key)
	if err != nil {
		return "", err
	}
	return p + ".meta", nil
}

// WriteMeta stores opaque metadata alongside an already-cached key. The
// caller decides the encoding - cache only persists bytes. Best-effort by
// design: a caller that fails to read it back later should fall back to
// its own default, not treat a missing sidecar as corruption.
func (c *Cache) WriteMeta(key string, data []byte) error {
	p, err := c.metaPath(key)
	if err != nil {
		return err
	}
	return os.WriteFile(p, data, 0o644)
}

// ReadMeta reads back metadata written by WriteMeta for key, or returns an
// error (including a plain "not exist") if none was ever written.
func (c *Cache) ReadMeta(key string) ([]byte, error) {
	p, err := c.metaPath(key)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(p)
}
