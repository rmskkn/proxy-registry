package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"registry-proxy/internal/aria2"
	"registry-proxy/internal/cache"
	"registry-proxy/internal/config"
)

// largeFetchSize is big enough that aria2 splits it across connections and
// the response is streamed rather than buffered, while still costing only a
// few seconds over loopback.
const largeFetchSize = 256 << 20

// writeLargeFile fills path with deterministic pseudo-random bytes and
// returns their sha256. Random-looking content keeps a transport that
// silently repeats or drops a chunk from producing a matching digest.
func writeLargeFile(t *testing.T, path string, size int64) string {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	sum := sha256.New()
	src := rand.New(rand.NewSource(1))
	buf := make([]byte, 1<<20)
	for remaining := size; remaining > 0; {
		chunk := int64(len(buf))
		if chunk > remaining {
			chunk = remaining
		}
		src.Read(buf[:chunk])
		if _, err := f.Write(buf[:chunk]); err != nil {
			t.Fatal(err)
		}
		sum.Write(buf[:chunk])
		remaining -= chunk
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(sum.Sum(nil))
}

// TestFetchGenericLargeFileThroughAria2 is the large-download case the
// proxy exists for: a quarter-gigabyte body, fetched through aria2 over
// several connections (so Range handling, the early-200 gate, and the
// cache's tmp-then-commit path all run on something bigger than a test
// fixture), served back byte-exact, then served again from the cache.
func TestFetchGenericLargeFileThroughAria2(t *testing.T) {
	if testing.Short() {
		t.Skip("large download skipped in -short mode")
	}
	requireAria2DockerImage(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "payload.bin")
	wantDigest := writeLargeFile(t, path, largeFetchSize)

	// http.ServeFile gives the upstream real Range and HEAD support, which
	// is what lets aria2 use more than one connection.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeFile(w, r, path)
	}))
	defer upstream.Close()

	cacheDir := t.TempDir()
	c, err := cache.New(cacheDir)
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}
	cfg := &config.Config{
		CacheDir:         cacheDir,
		HTTPTimeout:      60 * time.Second,
		MinAria2Size:     1 << 20,
		Aria2RPCPort:     16890,
		Aria2Connections: 8,
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

	fetch := func(attempt string) {
		resp, err := srv.Client().Get(srv.URL + "/fetch?url=" + url.QueryEscape(upstream.URL+"/payload.bin"))
		if err != nil {
			t.Fatalf("%s: %v", attempt, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200", attempt, resp.StatusCode)
		}
		if got := resp.Header.Get("Content-Length"); got != strconv.FormatInt(largeFetchSize, 10) {
			t.Errorf("%s: Content-Length = %q, want %d", attempt, got, largeFetchSize)
		}
		sum := sha256.New()
		n, err := io.Copy(sum, resp.Body)
		if err != nil {
			t.Fatalf("%s: reading body after %d bytes: %v", attempt, n, err)
		}
		if n != largeFetchSize {
			t.Errorf("%s: read %d bytes, want %d", attempt, n, largeFetchSize)
		}
		if got := hex.EncodeToString(sum.Sum(nil)); got != wantDigest {
			t.Errorf("%s: sha256 = %s, want %s", attempt, got, wantDigest)
		}
	}

	fetch("fresh download")
	fetch("cache hit")

	// A committed download leaves nothing behind in the cache's scratch dir -
	// worth checking on a file this size, since a leak costs real disk.
	entries, err := os.ReadDir(c.TmpDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("%d leftover file(s) in %s after a committed download", len(entries), c.TmpDir())
	}
}
