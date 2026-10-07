package proxy

import (
	"context"
	"net"
	"testing"
	"time"
)

// fakeDNSServer answers exactly one A-record query over UDP with ip, then
// exits - enough to drive queryA through a real wire round trip.
func fakeDNSServer(t *testing.T, ip string) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	go func() {
		buf := make([]byte, 512)
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		query := buf[:n]
		// Response: same header/ID with QR+RA set, question echoed back,
		// one answer record pointing at the question's name via a
		// compression pointer (0xC00C - straight after the 12-byte header).
		resp := append([]byte{}, query[0], query[1], 0x81, 0x80)
		resp = append(resp, query[4], query[5]) // QDCOUNT, unchanged
		resp = append(resp, 0x00, 0x01)         // ANCOUNT=1
		resp = append(resp, 0x00, 0x00, 0x00, 0x00)
		resp = append(resp, query[12:]...) // echoed question section
		resp = append(resp,
			0xC0, 0x0C, // NAME: pointer to question at offset 12
			0x00, 0x01, // TYPE=A
			0x00, 0x01, // CLASS=IN
			0x00, 0x00, 0x00, 0x3C, // TTL
			0x00, 0x04, // RDLENGTH=4
		)
		resp = append(resp, net.ParseIP(ip).To4()...)
		conn.WriteTo(resp, addr)
	}()

	return conn.LocalAddr().String()
}

func TestQueryAResolvesOverUDP(t *testing.T) {
	const wantIP = "203.0.113.7"
	serverAddr := fakeDNSServer(t, wantIP)

	got, err := queryA("example.invalid", serverAddr)
	if err != nil {
		t.Fatalf("queryA: %v", err)
	}
	if got != wantIP {
		t.Errorf("queryA = %q, want %q", got, wantIP)
	}
}

func TestQueryATimesOutWhenServerSilent(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer conn.Close()

	start := time.Now()
	_, err = queryA("example.invalid", conn.LocalAddr().String())
	if err == nil {
		t.Fatal("queryA succeeded against a server that never replies")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("queryA took %s, want it bounded by its own read deadline", elapsed)
	}
}

func TestDialBypassingHostsDialsIPLiteralDirectly(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	conn, err := dialBypassingHosts(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dialBypassingHosts: %v", err)
	}
	conn.Close()
}
