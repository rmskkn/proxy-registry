// Package config holds all runtime-tunable settings for the proxy, read
// from ~/registry-proxy/config.
package config

import (
	"log"
	"os"
	"path/filepath"
	"time"
)

// Config holds all runtime-tunable settings for the proxy.
type Config struct {
	Listen string

	// MITM, if true, makes Listen accept TLS connections (sniffed per
	// connection, alongside plain HTTP) by terminating them with a
	// locally-generated CA (see internal/mitmca) and serving any host
	// through the same pipeline as /fetch?url=.... Disabled by default: it
	// only matters for clients pointed at the proxy out-of-band (e.g. via
	// /etc/hosts or an iptables REDIRECT), and requires installing CADir's
	// CA certificate into those clients' trust stores.
	MITM  bool
	CADir string

	CacheDir string

	Aria2RPCPort     int
	Aria2Connections int
	Aria2MinSplit    string

	// NetrcPath is a netrc(5)-format file; a host it names gets its
	// credentials sent as HTTP Basic auth on generic /fetch requests.
	// Defaults to ~/.netrc; aria2c has no netrc support, so this is parsed
	// and applied by registry-proxy itself, not passed through to it.
	NetrcPath string

	MinAria2Size int64 // blobs smaller than this are fetched directly, bypassing aria2
	HTTPTimeout  time.Duration

	// InsecureRegistries lists upstream hosts (host or host:port) to talk to
	// over plain HTTP instead of HTTPS. Use "*" to use HTTP for every
	// upstream.
	InsecureRegistries []string
}

func defaults() *Config {
	cacheDir := "./cache"
	netrcPath := ""
	if home, err := os.UserHomeDir(); err == nil {
		cacheDir = filepath.Join(home, "registry-proxy", "cache")
		netrcPath = filepath.Join(home, ".netrc")
	}
	return &Config{
		Listen:           ":5000",
		MITM:             false,
		CADir:            "./ca",
		CacheDir:         cacheDir,
		Aria2RPCPort:     6880,
		Aria2Connections: 16,
		Aria2MinSplit:    "5M",
		NetrcPath:        netrcPath,
		MinAria2Size:     1 << 20,
		HTTPTimeout:      30 * time.Second,
	}
}

// Load builds a Config from built-in defaults overridden by
// ~/registry-proxy/config, if present.
func Load() *Config {
	c := defaults()
	path, err := filePath()
	if err != nil {
		return c // no home directory available; fall back to defaults
	}
	if err := applyFile(c, path); err != nil {
		log.Fatalf("registry-proxy: %v", err)
	}
	return c
}
