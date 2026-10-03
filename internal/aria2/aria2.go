// Package aria2 drives a local aria2c daemon over its JSON-RPC interface to
// perform segmented, multi-connection downloads of blobs, which is where the
// actual pull speedup over a plain HTTP GET comes from.
package aria2

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"registry-proxy/internal/config"
)

// Aria2 is a handle to a locally-spawned aria2c daemon.
type Aria2 struct {
	rpcURL string
	http   *http.Client
	cmd    *exec.Cmd
}

// Start launches aria2c in RPC daemon mode and waits for it to become ready.
func Start(cfg *config.Config) (*Aria2, error) {
	args := []string{
		"--enable-rpc",
		"--rpc-listen-port=" + strconv.Itoa(cfg.Aria2RPCPort),
		"--rpc-listen-all=false",
		"--allow-overwrite=true",
		"--auto-file-renaming=false",
		"--file-allocation=none",
		"--quiet=true",
		"--continue=true",
	}
	cmd := exec.Command(cfg.Aria2Path, args...)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting %s: %w", cfg.Aria2Path, err)
	}
	a := &Aria2{
		rpcURL: fmt.Sprintf("http://127.0.0.1:%d/jsonrpc", cfg.Aria2RPCPort),
		http:   &http.Client{Timeout: 10 * time.Second},
		cmd:    cmd,
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
	cmd.Process.Kill()
	return nil, fmt.Errorf("aria2c RPC did not become ready: %w", lastErr)
}

// Stop kills the aria2c subprocess.
func (a *Aria2) Stop() {
	if a.cmd != nil && a.cmd.Process != nil {
		a.cmd.Process.Kill()
	}
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

// Download fetches url into dir/out using multiple connections, optionally
// verifying the result against a sha-256 checksum via aria2's own
// --checksum support, and blocks until it completes, fails, or ctx is done.
// onStart, if non-nil, is invoked once aria2 has accepted and begun the
// download (i.e. addUri succeeded), before Download blocks on completion.
func (a *Aria2) Download(ctx context.Context, url string, headers []string, dir, out string, connections int, minSplit string, sha256Hex string, onStart func()) error {
	opts := map[string]interface{}{
		"dir":                       dir,
		"out":                       out,
		"split":                     strconv.Itoa(connections),
		"max-connection-per-server": strconv.Itoa(connections),
		"min-split-size":            minSplit,
	}
	if len(headers) > 0 {
		opts["header"] = headers
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

	if onStart != nil {
		onStart()
	}

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			a.call("aria2.remove", []interface{}{gid})
			return ctx.Err()
		case <-ticker.C:
			status, err := a.call("aria2.tellStatus", []interface{}{gid, []string{"status", "errorMessage"}})
			if err != nil {
				return err
			}
			var st struct {
				Status       string `json:"status"`
				ErrorMessage string `json:"errorMessage"`
			}
			if err := json.Unmarshal(status, &st); err != nil {
				return err
			}
			switch st.Status {
			case "complete":
				return nil
			case "error":
				return fmt.Errorf("aria2 download failed: %s", st.ErrorMessage)
			case "removed":
				return fmt.Errorf("aria2 download was removed")
			}
		}
	}
}
