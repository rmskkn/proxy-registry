package aria2

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"registry-proxy/internal/config"
)

func TestFirstNameserver(t *testing.T) {
	cases := []struct {
		name    string
		data    string
		want    string
		wantErr bool
	}{
		{"simple", "nameserver 1.2.3.4\n", "1.2.3.4", false},
		{"first of several", "nameserver 1.2.3.4\nnameserver 5.6.7.8\n", "1.2.3.4", false},
		{"leading comment and blank line", "# comment\n\nnameserver 9.9.9.9\n", "9.9.9.9", false},
		{"other directives ignored", "search example.com\noptions edns0\nnameserver 8.8.8.8\n", "8.8.8.8", false},
		{"none present", "search example.com\n", "", true},
		{"empty", "", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := firstNameserver([]byte(tc.data))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("firstNameserver(%q) = %q, want error", tc.data, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("firstNameserver(%q): %v", tc.data, err)
			}
			if got != tc.want {
				t.Errorf("firstNameserver(%q) = %q, want %q", tc.data, got, tc.want)
			}
		})
	}
}

func TestWriteDNSIsolationFiles(t *testing.T) {
	dir, err := writeDNSIsolationFiles("10.0.0.1")
	if err != nil {
		t.Fatalf("writeDNSIsolationFiles: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	hosts, err := os.ReadFile(filepath.Join(dir, "hosts"))
	if err != nil {
		t.Fatalf("reading hosts: %v", err)
	}
	if len(hosts) != 0 {
		t.Errorf("hosts file = %q, want empty", hosts)
	}

	resolv, err := os.ReadFile(filepath.Join(dir, "resolv.conf"))
	if err != nil {
		t.Fatalf("reading resolv.conf: %v", err)
	}
	if string(resolv) != "nameserver 10.0.0.1\n" {
		t.Errorf("resolv.conf = %q, want %q", resolv, "nameserver 10.0.0.1\n")
	}
}

// requireDockerImage skips the test unless both docker and dockerImage are
// available, since building the image isn't something a plain `go test`
// run should require.
func requireDockerImage(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not found in PATH")
	}
	if err := exec.Command("docker", "image", "inspect", dockerImage).Run(); err != nil {
		t.Skipf("%s not built, skipping (see docker/aria2)", dockerImage)
	}
}

func TestStartMissingDockerBinaryFails(t *testing.T) {
	t.Setenv("PATH", "")
	cfg := &config.Config{Aria2RPCPort: 16881, CacheDir: t.TempDir()}
	if _, err := Start(cfg); err == nil {
		t.Error("Start with no docker binary in PATH should fail")
	}
}

// TestStartAndStop is also a regression test: aria2.Start used to
// bind-mount the process's CWD at --workdir, which broke under systemd (no
// WorkingDirectory= means CWD is "/", and "docker run -v /:/ --workdir /"
// is rejected by the daemon, so no container was ever created).
func TestStartAndStop(t *testing.T) {
	requireDockerImage(t)

	cfg := &config.Config{
		Aria2RPCPort: 16883,
		CacheDir:     t.TempDir(),
	}
	a, err := Start(cfg)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if a.containerName == "" {
		t.Fatal("containerName not set in docker mode")
	}
	out, err := exec.Command("docker", "ps", "--filter", "name="+a.containerName, "--format", "{{.Names}}").CombinedOutput()
	if err != nil {
		t.Fatalf("docker ps: %v", err)
	}
	if string(out) == "" {
		t.Fatal("container not running after Start")
	}

	a.Stop()
	// --rm removes the container asynchronously, slightly after "docker
	// stop" itself returns, so poll rather than checking once.
	deadline := time.Now().Add(3 * time.Second)
	for {
		out, err = exec.Command("docker", "ps", "-a", "--filter", "name="+a.containerName, "--format", "{{.Names}}").CombinedOutput()
		if err != nil {
			t.Fatalf("docker ps -a: %v", err)
		}
		if string(out) == "" {
			break
		}
		if time.Now().After(deadline) {
			t.Errorf("container %s still present 3s after Stop", a.containerName)
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
}
