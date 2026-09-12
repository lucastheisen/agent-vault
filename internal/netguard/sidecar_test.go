package netguard

import (
	"context"
	"net"
	"strings"
	"testing"
)

func TestIsPrivateSidecarIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		// Loopback and RFC-1918: where a cleartext sidecar may live.
		{"127.0.0.1", true},
		{"127.9.9.9", true},
		{"::1", true},
		{"10.1.2.3", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.1.1", true},
		{"fd00::1", true}, // IPv6 ULA

		// Public.
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"2606:4700::1111", false},

		// Metadata service: blocked even though it is not routable from
		// outside, because a filter hop aimed at it would be an SSRF
		// primitive.
		{"169.254.169.254", false},
		{"fd00:ec2::254", false},

		// Link-local and CGN are not a trusted private network an
		// operator chose; they are what misconfiguration looks like.
		{"169.254.1.1", false},
		{"100.64.0.1", false},

		// Just outside RFC-1918.
		{"172.15.255.255", false},
		{"172.32.0.0", false},
		{"11.0.0.1", false},
		{"192.167.255.255", false},
	}
	for _, tc := range tests {
		ip := net.ParseIP(tc.ip)
		if ip == nil {
			t.Fatalf("bad test IP %q", tc.ip)
		}
		if got := IsPrivateSidecarIP(ip); got != tc.want {
			t.Errorf("IsPrivateSidecarIP(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

// The cleartext dialer reaches loopback and refuses anything public,
// regardless of AGENT_VAULT_ALLOW_PRIVATE_RANGES — where an origin may
// live has no bearing on where a policy sidecar may live.
func TestPrivateOnlyDialContext(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	for _, allowPrivate := range []string{"", "false", "true"} {
		t.Setenv("AGENT_VAULT_ALLOW_PRIVATE_RANGES", allowPrivate)
		dial := PrivateOnlyDialContext()

		conn, err := dial(context.Background(), "tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("loopback dial with ALLOW_PRIVATE_RANGES=%q: %v", allowPrivate, err)
		}
		_ = conn.Close()

		if _, err := dial(context.Background(), "tcp", "8.8.8.8:80"); err == nil {
			t.Fatalf("public cleartext dial succeeded with ALLOW_PRIVATE_RANGES=%q", allowPrivate)
		} else if !strings.Contains(err.Error(), "only loopback and private") {
			t.Errorf("public dial error = %v, want the cleartext-hop refusal", err)
		}

		if _, err := dial(context.Background(), "tcp", "169.254.169.254:80"); err == nil {
			t.Fatalf("metadata dial succeeded with ALLOW_PRIVATE_RANGES=%q", allowPrivate)
		}
	}
}

func TestPrivateOnlyDialContextRejectsMalformedAddress(t *testing.T) {
	dial := PrivateOnlyDialContext()
	if _, err := dial(context.Background(), "tcp", "no-port-here"); err == nil {
		t.Fatal("dial to an address with no port succeeded")
	}
}
