package shieldclient

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
)

// PROXY protocol version 2 (haproxy.org/download/2.9/doc/proxy-protocol.txt): a binary header at the start of
// a TCP connection that says who the real client is. The edge sends one to the origin so the game server can
// see the player's address instead of the node's.

// ProxySig is the 12 bytes every version 2 header starts with.
var ProxySig = []byte("\r\n\r\n\x00\r\nQUIT\n")

// ProxyHeader is a parsed header. Local is true for a LOCAL header (a health check by the sender itself);
// then Src and Dst are not set.
type ProxyHeader struct {
	Local    bool
	Src, Dst netip.AddrPort
}

// AppendProxyV2 appends a PROXY v2 header for a TCP connection from src to dst. Two addresses of different
// families are both written as IPv6.
func AppendProxyV2(b []byte, src, dst netip.AddrPort) []byte {
	b = append(b, ProxySig...)
	s, d := src.Addr().Unmap(), dst.Addr().Unmap()
	if s.Is4() && d.Is4() {
		b = append(b, 0x21, 0x11, 0, 12) // v2 PROXY, TCP over IPv4, 12 bytes of addresses
		b = append(b, s.AsSlice()...)
		b = append(b, d.AsSlice()...)
	} else {
		s16, d16 := s.As16(), d.As16()
		b = append(b, 0x21, 0x21, 0, 36) // TCP over IPv6
		b = append(b, s16[:]...)
		b = append(b, d16[:]...)
	}
	b = binary.BigEndian.AppendUint16(b, src.Port())
	return binary.BigEndian.AppendUint16(b, dst.Port())
}

// AppendProxyV1 appends a PROXY v1 (text) header for a TCP connection from src to dst, like
// "PROXY TCP4 198.51.100.7 203.0.113.1 51000 30800\r\n". Two addresses of different families are written as IPv6.
func AppendProxyV1(b []byte, src, dst netip.AddrPort) []byte {
	s, d := src.Addr().Unmap(), dst.Addr().Unmap()
	fam := "TCP4"
	if !s.Is4() || !d.Is4() {
		fam = "TCP6"
		s, d = netip.AddrFrom16(s.As16()), netip.AddrFrom16(d.As16())
	}
	return fmt.Appendf(b, "PROXY %s %s %s %d %d\r\n", fam, s, d, src.Port(), dst.Port())
}

// AppendProxyV2Local appends a LOCAL header: the connection is the sender's own, there is no client to name.
func AppendProxyV2Local(b []byte) []byte {
	return append(append(b, ProxySig...), 0x20, 0x00, 0, 0)
}

// AddrPortOf turns a net.Addr from a TCP connection into a netip.AddrPort (zero if it is not one).
func AddrPortOf(a net.Addr) netip.AddrPort {
	if t, ok := a.(*net.TCPAddr); ok {
		return t.AddrPort()
	}
	ap, _ := netip.ParseAddrPort(a.String())
	return ap
}

var ErrNoProxyHeader = errors.New("no PROXY v2 header")

// HasProxyV2 says whether r starts with a PROXY v2 signature, waiting for at most the 12 bytes it needs.
func HasProxyV2(r *bufio.Reader) (bool, error) {
	p, err := r.Peek(len(ProxySig))
	if err != nil {
		return false, err
	}
	return bytes.Equal(p, ProxySig), nil
}

// ReadProxyV2 reads one PROXY v2 header from r. Extra TLVs after the addresses are skipped; a header of an
// address family other than TCP over IPv4 or IPv6 (UDP, unix sockets, UNSPEC) counts as LOCAL.
func ReadProxyV2(r io.Reader) (ProxyHeader, error) {
	var h ProxyHeader
	var fixed [16]byte
	if _, err := io.ReadFull(r, fixed[:]); err != nil {
		return h, err
	}
	if !bytes.Equal(fixed[:12], ProxySig) {
		return h, ErrNoProxyHeader
	}
	if fixed[12]>>4 != 2 {
		return h, fmt.Errorf("PROXY header version %d", fixed[12]>>4)
	}
	n := int(binary.BigEndian.Uint16(fixed[14:]))
	if n > 4096 {
		return h, fmt.Errorf("PROXY header of %d bytes", n)
	}
	rest := make([]byte, n)
	if _, err := io.ReadFull(r, rest); err != nil {
		return h, err
	}
	switch fixed[12] & 0x0f {
	case 0: // LOCAL
		h.Local = true
		return h, nil
	case 1: // PROXY
	default:
		return h, fmt.Errorf("PROXY header command %d", fixed[12]&0x0f)
	}
	switch fixed[13] {
	case 0x11:
		if n < 12 {
			return h, errors.New("short PROXY header")
		}
		h.Src = netip.AddrPortFrom(netip.AddrFrom4([4]byte(rest[0:4])), binary.BigEndian.Uint16(rest[8:]))
		h.Dst = netip.AddrPortFrom(netip.AddrFrom4([4]byte(rest[4:8])), binary.BigEndian.Uint16(rest[10:]))
	case 0x21:
		if n < 36 {
			return h, errors.New("short PROXY header")
		}
		h.Src = netip.AddrPortFrom(netip.AddrFrom16([16]byte(rest[0:16])).Unmap(), binary.BigEndian.Uint16(rest[32:]))
		h.Dst = netip.AddrPortFrom(netip.AddrFrom16([16]byte(rest[16:32])).Unmap(), binary.BigEndian.Uint16(rest[34:]))
	default:
		h.Local = true
	}
	return h, nil
}
