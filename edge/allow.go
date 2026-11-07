package main

import (
	"flag"
	"fmt"
	"net/netip"
	"strings"
)

// -allow-ips lists addresses many players share (a VPN exit, an office), which would otherwise run into the
// per-address limits. They are exempt from -max-per-ip and -token-ip-limit only: every connection still needs
// a valid token, each device keeps its own limit, and -max-conns still caps the total.
var allowIPs = flag.String("allow-ips", "", "comma separated IPs or CIDRs exempt from -max-per-ip and -token-ip-limit (addresses many players share, like a VPN exit); tokens, the per-device limit and -max-conns still apply")

var allowed []netip.Prefix

func parseAllow(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if p, err := netip.ParsePrefix(f); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(f)
		if err != nil {
			return nil, fmt.Errorf("-allow-ips: %q is not an IP or CIDR", f)
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

// isAllowed says whether the remote address ip (as net.SplitHostPort gives it) is in -allow-ips.
func isAllowed(ip string) bool {
	if len(allowed) == 0 {
		return false
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, p := range allowed {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
