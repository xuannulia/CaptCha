package nettrust

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

func ParseCIDRs(cidrs []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(cidrs))
	for _, cidr := range cidrs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(cidr)
		if err == nil {
			prefixes = append(prefixes, prefix.Masked())
			continue
		}
		addr, addrErr := netip.ParseAddr(cidr)
		if addrErr != nil {
			return nil, fmt.Errorf("invalid trusted proxy cidr %q: %w", cidr, err)
		}
		bits := 128
		if addr.Is4() {
			bits = 32
		}
		prefixes = append(prefixes, netip.PrefixFrom(addr, bits))
	}
	return prefixes, nil
}

func DirectIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return host
	}
	return remoteAddr
}

func Contains(prefixes []netip.Prefix, ip string) bool {
	if len(prefixes) == 0 || ip == "" {
		return false
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// ClientIP walks the forwarding chain from the nearest hop outwards and
// returns the first address that is not a configured trusted proxy.
func ClientIP(remoteAddr, forwardedFor string, trusted []netip.Prefix) string {
	direct := DirectIP(remoteAddr)
	if !Contains(trusted, direct) {
		return direct
	}
	chain := make([]string, 0, 4)
	for _, part := range strings.Split(forwardedFor, ",") {
		candidate := strings.TrimSpace(part)
		if _, err := netip.ParseAddr(candidate); err == nil {
			chain = append(chain, candidate)
		}
	}
	for i := len(chain) - 1; i >= 0; i-- {
		if !Contains(trusted, chain[i]) {
			return chain[i]
		}
	}
	return direct
}
