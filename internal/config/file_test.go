package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestApplyFileSetsFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	content := "# comment\n\nlisten = :9000\naria2-rpc-port=7000\nhttp-timeout = 5s\ninsecure-registries = a:1,b:2\nnetrc-path = /tmp/my-netrc\nmitm-tls = true\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	c := defaults()
	if err := applyFile(c, path); err != nil {
		t.Fatalf("applyFile: %v", err)
	}
	if c.Listen != ":9000" {
		t.Errorf("Listen = %q, want :9000", c.Listen)
	}
	if c.Aria2RPCPort != 7000 {
		t.Errorf("Aria2RPCPort = %d, want 7000", c.Aria2RPCPort)
	}
	if c.HTTPTimeout != 5*time.Second {
		t.Errorf("HTTPTimeout = %v, want 5s", c.HTTPTimeout)
	}
	if want := []string{"a:1", "b:2"}; len(c.InsecureRegistries) != 2 || c.InsecureRegistries[0] != want[0] || c.InsecureRegistries[1] != want[1] {
		t.Errorf("InsecureRegistries = %v, want %v", c.InsecureRegistries, want)
	}
	if !c.MITM {
		t.Error("MITM = false, want true")
	}
	if c.NetrcPath != "/tmp/my-netrc" {
		t.Errorf("NetrcPath = %q, want /tmp/my-netrc", c.NetrcPath)
	}
}

func TestApplyFileBadBoolRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	if err := os.WriteFile(path, []byte("mitm-tls = not-a-bool\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := applyFile(defaults(), path); err == nil {
		t.Error("expected error for malformed bool value, got nil")
	}
}

func TestApplyFileMissingIsNotAnError(t *testing.T) {
	c := defaults()
	if err := applyFile(c, filepath.Join(t.TempDir(), "does-not-exist")); err != nil {
		t.Errorf("missing config file should be silently ignored, got %v", err)
	}
}

func TestApplyFileUnknownKeyRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	if err := os.WriteFile(path, []byte("not-a-real-key = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := applyFile(defaults(), path); err == nil {
		t.Error("expected error for unknown config key, got nil")
	}
}

func TestApplyFileMalformedLineRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	if err := os.WriteFile(path, []byte("this line has no equals sign\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := applyFile(defaults(), path); err == nil {
		t.Error("expected error for malformed line, got nil")
	}
}

func TestApplyFileBadIntRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	if err := os.WriteFile(path, []byte("aria2-rpc-port = not-a-number\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := applyFile(defaults(), path); err == nil {
		t.Error("expected error for malformed int value, got nil")
	}
}

func TestFilePathUnderHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory available")
	}
	path, err := filePath()
	if err != nil {
		t.Fatalf("filePath: %v", err)
	}
	want := filepath.Join(home, "registry-proxy", "config")
	if path != want {
		t.Errorf("filePath() = %q, want %q", path, want)
	}
}
