package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultsNetrcPathUnderHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory available")
	}
	c := defaults()
	want := filepath.Join(home, ".netrc")
	if c.NetrcPath != want {
		t.Errorf("NetrcPath = %q, want %q", c.NetrcPath, want)
	}
}
