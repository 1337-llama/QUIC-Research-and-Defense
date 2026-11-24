// Package safety keeps the simulator pointed at lab infrastructure.
//
// By default the simulator may only talk to loopback, private (RFC 1918 and
// IPv6 ULA) and shared-address-space (RFC 6598) destinations. Reaching a
// public address requires an explicit, deliberately awkward opt-in.
package safety

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
)

// ErrNotLab is returned (wrapped) when a destination is outside the lab
// address ranges and public targets have not been allowed.
var ErrNotLab = errors.New("destination is not a lab address")

// cgnat is RFC 6598 shared address space, common in lab and container setups.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// Resolver looks up host names. *net.Resolver satisfies it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Policy decides which destinations are acceptable.
type Policy struct {
	// AllowPublic permits destinations outside the lab ranges.
	AllowPublic bool
}

// IsLabAddr reports whether a is in a range the simulator may use without
// AllowPublic.
func IsLabAddr(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsLoopback() || a.IsPrivate() || (a.Is4() && cgnat.Contains(a))
}

// CheckAddr returns an error if a is not an acceptable destination.
// Unspecified, multicast and broadcast addresses are always rejected.
func (p Policy) CheckAddr(a netip.Addr) error {
	a = a.Unmap()
	switch {
	case !a.IsValid():
		return errors.New("invalid address")
	case a.IsUnspecified(), a.IsMulticast(), a == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return fmt.Errorf("%s is not a unicast destination", a)
	case IsLabAddr(a), p.AllowPublic:
		return nil
	default:
		return fmt.Errorf("%s: %w (pass --allow-public-targets only for infrastructure you own)", a, ErrNotLab)
	}
}

// Resolve splits hostport, resolves the host, and returns every resulting
// address. It fails if any resolved address is unacceptable, so a name that
// resolves to a mix of lab and public addresses cannot slip through.
func (p Policy) Resolve(ctx context.Context, r Resolver, hostport string) ([]netip.AddrPort, error) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, fmt.Errorf("target %q: %w", hostport, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 {
		return nil, fmt.Errorf("target %q: invalid port %q", hostport, portStr)
	}

	var addrs []netip.Addr
	if a, perr := netip.ParseAddr(host); perr == nil {
		addrs = []netip.Addr{a}
	} else {
		if r == nil {
			return nil, fmt.Errorf("target %q: no resolver for host name", hostport)
		}
		addrs, err = r.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("resolving %q: %w", host, err)
		}
		if len(addrs) == 0 {
			return nil, fmt.Errorf("resolving %q: no addresses", host)
		}
	}

	out := make([]netip.AddrPort, 0, len(addrs))
	for _, a := range addrs {
		if err := p.CheckAddr(a); err != nil {
			return nil, fmt.Errorf("target %q: %w", hostport, err)
		}
		out = append(out, netip.AddrPortFrom(a.Unmap(), uint16(port)))
	}
	return out, nil
}
