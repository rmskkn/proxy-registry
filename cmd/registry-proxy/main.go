// Command registry-proxy is a universal, aria2-accelerated HTTP
// pull-through proxy for the Docker Registry HTTP API v2.
package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"registry-proxy/internal/aria2"
	"registry-proxy/internal/cache"
	"registry-proxy/internal/config"
	"registry-proxy/internal/mitmca"
	"registry-proxy/internal/proxy"
)

// run wires up cache/aria2/backend and returns the reason the process should
// exit. It never calls log.Fatal itself so the caller can guarantee the
// aria2 subprocess is cleaned up (log.Fatal skips deferred functions).
func run(cfg *config.Config) error {
	c, err := cache.New(cfg.CacheDir)
	if err != nil {
		return err
	}

	a, err := aria2.Start(cfg)
	if err != nil {
		return err
	}
	defer a.Stop()

	p := proxy.New(cfg, c, a)

	var tlsConfig *tls.Config
	if cfg.MITM {
		ca, err := mitmca.Load(cfg.CADir)
		if err != nil {
			return fmt.Errorf("loading MITM CA: %w", err)
		}
		tlsConfig = &tls.Config{GetCertificate: ca.GetCertificate}
	}

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	defer ln.Close()

	plainServer := &http.Server{Handler: p}
	var tlsServer *http.Server
	if tlsConfig != nil {
		tlsServer = &http.Server{Handler: http.HandlerFunc(p.ServeMITM)}
	}

	log.Printf("proxy listening on %s (cache=%s, aria2 connections=%d, mitm=%v)", cfg.Listen, cfg.CacheDir, cfg.Aria2Connections, tlsConfig != nil)

	errCh := make(chan error, 1)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				errCh <- err
				return
			}
			go serveConn(conn, plainServer, tlsServer, tlsConfig)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		return err
	case sig := <-sigCh:
		log.Printf("received %s, shutting down", sig)
		return nil
	}
}

// serveConn sniffs the first byte of conn to tell a TLS ClientHello (0x16)
// from plain HTTP, then hands it to the matching *http.Server. This lets a
// single port serve both - which is what makes it possible to point an
// iptables REDIRECT for ports 80 and 443 alike at this one port.
func serveConn(conn net.Conn, plain, tlsSrv *http.Server, tlsConfig *tls.Config) {
	br := bufio.NewReader(conn)
	first, err := br.Peek(1)
	if err != nil {
		conn.Close()
		return
	}
	pc := &peekedConn{Conn: conn, r: br}

	if first[0] == recordTypeHandshake {
		if tlsSrv == nil {
			conn.Close()
			return
		}
		tlsSrv.Serve(newOnceListener(tls.Server(pc, tlsConfig)))
		return
	}
	plain.Serve(newOnceListener(pc))
}

// recordTypeHandshake is the first byte of every TLS record carrying a
// handshake message (RFC 8446 ssec 5.1), which is always how a TLS
// connection starts - this is enough to distinguish it from a plain HTTP
// request line, which always starts with an ASCII method name.
const recordTypeHandshake = 0x16

// peekedConn re-reads through br, which has already buffered (and must
// replay) the byte peeked in serveConn.
type peekedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *peekedConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// onceListener adapts a single already-accepted net.Conn into the
// net.Listener shape *http.Server.Serve expects, so the standard library's
// own request parsing/keep-alive/TLS handshake handling can be reused for
// one connection at a time instead of reimplementing it.
type onceListener struct {
	conn net.Conn
	used bool
}

func newOnceListener(c net.Conn) *onceListener { return &onceListener{conn: c} }

func (l *onceListener) Accept() (net.Conn, error) {
	if l.used {
		return nil, io.EOF
	}
	l.used = true
	return l.conn, nil
}

func (l *onceListener) Close() error   { return nil }
func (l *onceListener) Addr() net.Addr { return l.conn.LocalAddr() }

func main() {
	cfg := config.Load()
	if err := run(cfg); err != nil {
		log.Println(err)
		os.Exit(1)
	}
}
