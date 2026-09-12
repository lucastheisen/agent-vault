package mitm

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/netguard"
)

// filterTransport builds a dedicated hop transport. It does not honor
// AGENT_VAULT_ALLOW_PRIVATE_RANGES. HTTPS allows public destinations
// (IMDS still blocked). HTTP is loopback-only unless
// allow_insecure_private_http is set, in which case every resolved
// address must be loopback or RFC1918.
func filterTransport(f *broker.Filter) *http.Transport {
	allowInsecure := f != nil && f.AllowInsecurePrivateHTTP
	scheme := ""
	hostname := ""
	if f != nil {
		if u, err := parseFilterURL(f.URL); err == nil {
			scheme = u.scheme
			hostname = u.host
		}
	}
	return &http.Transport{
		DialContext:           filterDialContext(scheme, hostname, allowInsecure),
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:     false,
		DisableKeepAlives:     false,
		MaxIdleConns:          32,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 5 * time.Minute,
		// ReverseProxy uses Transport.RoundTrip — no redirect follow.
	}
}

type parsedFilterURL struct {
	scheme string
	host   string
}

func parseFilterURL(raw string) (parsedFilterURL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return parsedFilterURL{}, fmt.Errorf("invalid filter url")
	}
	return parsedFilterURL{scheme: u.Scheme, host: u.Hostname()}, nil
}

func filterDialContext(scheme, hostname string, allowInsecurePrivate bool) func(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	httpsDial := netguard.SafeDialContext(true) // public + private; IMDS blocked

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("filter dial: invalid address %q: %w", addr, err)
		}
		if scheme == "https" {
			return httpsDial(ctx, network, addr)
		}

		// http
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return dialer.DialContext(ctx, network, addr)
		}
		if !allowInsecurePrivate {
			return nil, fmt.Errorf("filter dial: cleartext http to %q requires a loopback IP or allow_insecure_private_http", host)
		}

		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("filter dial: DNS lookup failed for %q: %w", host, err)
		}
		for _, ipAddr := range ips {
			if !filterHTTPIPAllowed(ipAddr.IP) {
				return nil, fmt.Errorf("filter dial: resolved address %s for %q is not loopback or RFC1918", ipAddr.IP, host)
			}
		}
		return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
	}
}

func filterHTTPIPAllowed(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	// IMDS / link-local always blocked.
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 169 && ip4[1] == 254 {
			return false
		}
		// RFC1918
		if ip4[0] == 10 {
			return true
		}
		if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			return true
		}
		if ip4[0] == 192 && ip4[1] == 168 {
			return true
		}
		return false
	}
	return false
}
