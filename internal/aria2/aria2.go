// Package aria2 drives an aria2c daemon, running in a container, over its
// JSON-RPC interface to perform segmented, multi-connection downloads of
// blobs, which is where the actual pull speedup over a plain HTTP GET comes
// from.
package aria2

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"registry-proxy/internal/config"
)

// Aria2 is a handle to an aria2c daemon running in a container (see Start).
type Aria2 struct {
	rpcURL        string
	http          *http.Client
	cmd           *exec.Cmd
	containerName string
	dnsDir        string
}

// dockerImage is the aria2c image Start runs (see docker/aria2).
const dockerImage = "registry-proxy-aria2:local"

// Start launches aria2c in RPC daemon mode, inside dockerImage, and waits
// for it to become ready.
//
// aria2c always runs in a container with /etc/hosts emptied and
// /etc/resolv.conf pinned to the host's real nameserver, so its DNS
// resolution is isolated from the host's /etc/hosts (e.g. mitm-tls
// entries). --network host keeps the RPC port reachable on 127.0.0.1 as if
// aria2c ran locally; bind-mounting cfg.CacheDir's absolute path at the
// same path keeps the --dir/--out paths passed over RPC valid inside the
// container too.
func Start(cfg *config.Config) (*Aria2, error) {
	ns, err := hostDNSServer()
	if err != nil {
		return nil, fmt.Errorf("reading host DNS server: %w", err)
	}
	dnsDir, err := writeDNSIsolationFiles(ns)
	if err != nil {
		return nil, fmt.Errorf("preparing aria2 DNS isolation files: %w", err)
	}
	cacheDir, err := filepath.Abs(cfg.CacheDir)
	if err != nil {
		os.RemoveAll(dnsDir)
		return nil, fmt.Errorf("resolving cache dir: %w", err)
	}
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		os.RemoveAll(dnsDir)
		return nil, fmt.Errorf("creating cache dir: %w", err)
	}

	containerName := "registry-proxy-aria2-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	dockerArgs := []string{
		"run", "--rm",
		"--name", containerName,
		// Image has no USER; without this, files land root-owned on the
		// host, undeletable by the proxy's own user.
		"--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		"--network", "host",
		"-v", filepath.Join(dnsDir, "hosts") + ":/etc/hosts:ro",
		"-v", filepath.Join(dnsDir, "resolv.conf") + ":/etc/resolv.conf:ro",
		"-v", cacheDir + ":" + cacheDir,
		"--workdir", cacheDir,
		dockerImage,
		"aria2c",
		"--async-dns=true",
		"--enable-rpc",
		"--rpc-listen-port=" + strconv.Itoa(cfg.Aria2RPCPort),
		"--rpc-listen-all=false",
		"--allow-overwrite=true",
		"--auto-file-renaming=false",
		"--file-allocation=none",
		"--continue=true",
	}
	cmd := exec.Command("docker", dockerArgs...)

	if err := cmd.Start(); err != nil {
		os.RemoveAll(dnsDir)
		return nil, fmt.Errorf("starting aria2c: %w", err)
	}
	a := &Aria2{
		rpcURL:        fmt.Sprintf("http://127.0.0.1:%d/jsonrpc", cfg.Aria2RPCPort),
		http:          &http.Client{Timeout: 10 * time.Second},
		cmd:           cmd,
		containerName: containerName,
		dnsDir:        dnsDir,
	}
	deadline := time.Now().Add(5 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		if _, err := a.call("aria2.getVersion", []interface{}{}); err == nil {
			return a, nil
		} else {
			lastErr = err
		}
		time.Sleep(100 * time.Millisecond)
	}
	a.Stop()
	return nil, fmt.Errorf("aria2c RPC did not become ready: %w", lastErr)
}

// writeDNSIsolationFiles writes an empty hosts file and a resolv.conf
// pinned to nameserver into a fresh temp dir, for bind-mounting into the
// aria2 container.
func writeDNSIsolationFiles(nameserver string) (string, error) {
	dir, err := os.MkdirTemp("", "registry-proxy-aria2-dns-")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "hosts"), nil, 0o644); err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "resolv.conf"), []byte("nameserver "+nameserver+"\n"), 0o644); err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	return dir, nil
}

// hostDNSServer returns the first nameserver listed in the host's
// /etc/resolv.conf.
func hostDNSServer() (string, error) {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return "", err
	}
	return firstNameserver(data)
}

// firstNameserver returns the first "nameserver" line's address from
// resolv.conf-format data.
func firstNameserver(data []byte) (string, error) {
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "nameserver" {
			return fields[1], nil
		}
	}
	return "", fmt.Errorf("no nameserver found")
}

// Stop stops the container, then kills the local docker-run client process
// - killing only the client would otherwise leave an orphaned --rm
// container running (it doesn't relay SIGKILL to the container).
func (a *Aria2) Stop() {
	exec.Command("docker", "stop", a.containerName).Run()
	if a.cmd != nil && a.cmd.Process != nil {
		a.cmd.Process.Kill()
	}
	os.RemoveAll(a.dnsDir)
}

func (a *Aria2) call(method string, params []interface{}) (json.RawMessage, error) {
	reqBody, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "proxy",
		"method":  method,
		"params":  params,
	})
	resp, err := a.http.Post(a.rpcURL, "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if out.Error != nil {
		return nil, fmt.Errorf("aria2 %s: %s", method, out.Error.Message)
	}
	return out.Result, nil
}

// DownloadError carries aria2's own error code for a failed download task,
// so callers can map it to an HTTP status instead of guessing from text.
type DownloadError struct {
	Code    int
	Message string
}

func (e *DownloadError) Error() string {
	return fmt.Sprintf("aria2 download failed (errorCode=%d): %s", e.Code, e.Message)
}

// BasicCreds are basic-auth credentials for a download's initial host, sent
// only after a 401 challenge - unlike an Authorization header, which aria2
// would re-send even to a pre-signed redirect target that rejects it.
type BasicCreds struct {
	User     string
	Password string
}

// Download fetches url into dir/out using multiple connections, optionally
// verifying the result against a sha-256 checksum via aria2's own
// --checksum support, and blocks until it completes, fails, or ctx is done.
// A failure aria2 reports for the task itself is returned as a
// *DownloadError.
//
// onStarted fires at most once, on the first real progress (totalLength or
// completedLength > 0) - never on addUri's gid alone, and never on a 404 or
// a download that completes before onStarted would fire.
func (a *Aria2) Download(ctx context.Context, url string, headers []string, creds *BasicCreds, dir, out string, connections int, minSplit string, sha256Hex string, onStarted func(totalLength int64)) error {
	opts := map[string]interface{}{
		"dir":                       dir,
		"out":                       out,
		"split":                     strconv.Itoa(connections),
		"max-connection-per-server": strconv.Itoa(connections),
		"min-split-size":            minSplit,
		// Default retry-wait=0 exhausts max-tries instantly against a
		// server throttling parallel connections (e.g. 429s).
		"retry-wait": "3",
		"max-tries":  "10",
	}
	if len(headers) > 0 {
		opts["header"] = headers
	}
	if creds != nil {
		// http-auth-challenge defaults to false, which would send creds
		// to every host including redirect targets - must be explicit.
		opts["http-user"] = creds.User
		opts["http-passwd"] = creds.Password
		opts["http-auth-challenge"] = "true"
	}
	if sha256Hex != "" {
		opts["checksum"] = "sha-256=" + strings.ToLower(sha256Hex)
	}
	res, err := a.call("aria2.addUri", []interface{}{[]string{url}, opts})
	if err != nil {
		return err
	}
	var gid string
	if err := json.Unmarshal(res, &gid); err != nil {
		return err
	}

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	started := false
	for {
		select {
		case <-ctx.Done():
			a.call("aria2.remove", []interface{}{gid})
			return ctx.Err()
		case <-ticker.C:
			status, err := a.call("aria2.tellStatus", []interface{}{gid, []string{"status", "totalLength", "completedLength", "errorCode", "errorMessage"}})
			if err != nil {
				return err
			}
			// aria2 reports totalLength, completedLength and errorCode as
			// decimal strings, not numbers.
			var st struct {
				Status          string `json:"status"`
				TotalLength     string `json:"totalLength"`
				CompletedLength string `json:"completedLength"`
				ErrorCode       string `json:"errorCode"`
				ErrorMessage    string `json:"errorMessage"`
			}
			if err := json.Unmarshal(status, &st); err != nil {
				return err
			}
			switch st.Status {
			case "complete":
				return nil
			case "error":
				code, _ := strconv.Atoi(st.ErrorCode)
				return &DownloadError{Code: code, Message: st.ErrorMessage}
			case "removed":
				return fmt.Errorf("aria2 download was removed")
			case "active":
				if onStarted != nil && !started {
					totalLength, _ := strconv.ParseInt(st.TotalLength, 10, 64)
					completedLength, _ := strconv.ParseInt(st.CompletedLength, 10, 64)
					if totalLength > 0 || completedLength > 0 {
						started = true
						onStarted(totalLength)
					}
				}
			}
		}
	}
}
