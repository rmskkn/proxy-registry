package proxy

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"

	"registry-proxy/internal/aria2"
)

func dialBypassingHosts(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{}
	if net.ParseIP(host) != nil {
		return dialer.DialContext(ctx, network, addr)
	}
	ip, err := resolveViaRealNameserver(host)
	if err != nil {
		return nil, err
	}
	return dialer.DialContext(ctx, network, net.JoinHostPort(ip, port))
}

func resolveViaRealNameserver(host string) (string, error) {
	ns, err := aria2.HostDNSServer()
	if err != nil {
		return "", fmt.Errorf("reading host DNS server: %w", err)
	}
	return queryA(host, net.JoinHostPort(ns, "53"))
}

func queryA(host, nameserverAddr string) (string, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(host), dns.TypeA)
	msg.RecursionDesired = true

	client := new(dns.Client)
	client.Timeout = 3 * time.Second
	resp, _, err := client.Exchange(msg, nameserverAddr)
	if err != nil {
		return "", err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return "", fmt.Errorf("dns: query failed with rcode %s", dns.RcodeToString[resp.Rcode])
	}
	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok {
			return a.A.String(), nil
		}
	}
	return "", fmt.Errorf("dns: no A record for query")
}
