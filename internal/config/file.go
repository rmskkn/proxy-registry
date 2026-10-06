package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// filePath returns the path to the config file: ~/registry-proxy/config.
func filePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "registry-proxy", "config"), nil
}

// setters maps config-file keys to the Config field they populate.
func setters(c *Config) map[string]func(string) error {
	return map[string]func(string) error{
		"listen": func(v string) error { c.Listen = v; return nil },
		"mitm-tls": func(v string) error {
			b, err := strconv.ParseBool(v)
			if err != nil {
				return err
			}
			c.MITM = b
			return nil
		},
		"ca-dir":    func(v string) error { c.CADir = v; return nil },
		"cache-dir": func(v string) error { c.CacheDir = v; return nil },
		"aria2-rpc-port": func(v string) error {
			n, err := strconv.Atoi(v)
			if err != nil {
				return err
			}
			c.Aria2RPCPort = n
			return nil
		},
		"aria2-connections": func(v string) error {
			n, err := strconv.Atoi(v)
			if err != nil {
				return err
			}
			c.Aria2Connections = n
			return nil
		},
		"aria2-min-split-size": func(v string) error { c.Aria2MinSplit = v; return nil },
		"netrc-path":           func(v string) error { c.NetrcPath = v; return nil },
		"min-aria2-size": func(v string) error {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return err
			}
			c.MinAria2Size = n
			return nil
		},
		"http-timeout": func(v string) error {
			d, err := time.ParseDuration(v)
			if err != nil {
				return err
			}
			c.HTTPTimeout = d
			return nil
		},
		"insecure-registries": func(v string) error {
			c.InsecureRegistries = strings.Split(v, ",")
			return nil
		},
	}
}

// applyFile reads path as "key = value" lines (blank lines and lines
// starting with "#" ignored) and applies each key onto c. A missing file is
// not an error; an unknown key or malformed value is.
func applyFile(c *Config, path string) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	set := setters(c)
	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return fmt.Errorf("%s:%d: expected key=value, got %q", path, lineNo, line)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		fn, known := set[key]
		if !known {
			return fmt.Errorf("%s:%d: unknown config key %q", path, lineNo, key)
		}
		if err := fn(value); err != nil {
			return fmt.Errorf("%s:%d: %s: %w", path, lineNo, key, err)
		}
	}
	return scanner.Err()
}
