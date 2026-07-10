package nettrust

import "testing"

func TestClientIPUsesNearestUntrustedForwardedHop(t *testing.T) {
	trusted, err := ParseCIDRs([]string{"192.0.2.0/24", "10.0.0.0/8"})
	if err != nil {
		t.Fatalf("parse trusted proxies: %v", err)
	}
	got := ClientIP("192.0.2.10:443", "198.51.100.99, 203.0.113.8, 10.0.0.4", trusted)
	if got != "203.0.113.8" {
		t.Fatalf("expected nearest untrusted address, got %q", got)
	}
}

func TestClientIPIgnoresForwardingFromUntrustedPeer(t *testing.T) {
	trusted, err := ParseCIDRs([]string{"192.0.2.0/24"})
	if err != nil {
		t.Fatalf("parse trusted proxies: %v", err)
	}
	got := ClientIP("198.51.100.20:443", "203.0.113.9", trusted)
	if got != "198.51.100.20" {
		t.Fatalf("expected direct peer address, got %q", got)
	}
}
