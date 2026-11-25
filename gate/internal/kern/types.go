package kern

import (
	"fmt"
	"net/netip"
	"strings"
)

// Go views of the structs in bpf/gate.h.
type (
	Cfg     = gateGateCfg
	IPState = gateIpState
	BanVal  = gateBanVal
	Ctr     = gateCtr
	LpmKey  = gateLpmKey
	AddrKey = gateAddrKey
	FlowKey = gateFlowKey
)

// Event is one "address banned" notice from the kernel (struct event).
type Event struct {
	Ts      uint64
	Bytes   uint64
	A       [16]byte
	Reason  uint32
	Score   uint32
	Strikes uint32
	BanSecs uint32
	Pkts    uint32
	Tcp     uint32
	Udp     uint32
	Icmp    uint32
	Syn     uint32
	Pad     uint32
}

// Settings switches, as in gate.h.
const (
	FEnabled uint32 = 1 << iota
	FObserve
	FDropBogon
	FDropPrivate
	FDropBadTCP
	FDropFrags
	FDropFragsAttack
	FAmp
	FReflect
	FRate
	FToken
	FNewSrc
	FPanic
	FAttack
	FTrack
	FHasAllow
	FHasSubnets
)

// Counter slots, as in gate.h.
const (
	CSeen = iota
	CPass
	CPassNonIP
	CPassAllow
	CPassLocal
	CDropBanned
	CDropSubnet
	CDropPanic
	CDropMalformed
	CDropBogon
	CDropPrivate
	CDropTCPFlags
	CDropFrag
	CDropAmp
	CDropReflect
	CDropNewSrc
	CDropToken
	CDropCap
	CDropRate
	CWouldDrop
	CTCP
	CUDP
	CICMP
	CSYN
	COther
	CNewSrc
	CNewBan
	CMax = 32
)

// DropSlots are the counter slots that mean "dropped", in pipeline order.
var DropSlots = []int{
	CDropBanned, CDropSubnet, CDropPanic, CDropMalformed, CDropBogon, CDropPrivate,
	CDropTCPFlags, CDropFrag, CDropAmp, CDropReflect, CDropNewSrc, CDropToken,
	CDropCap, CDropRate,
}

// SlotName gives the plain-words label for a counter slot.
func SlotName(slot int) string {
	switch slot {
	case CSeen:
		return "Seen"
	case CPass:
		return "Passed"
	case CPassNonIP:
		return "Passed (not IP)"
	case CPassAllow:
		return "Passed (allow list)"
	case CPassLocal:
		return "Passed (local network)"
	case CDropBanned:
		return "Banned address"
	case CDropSubnet:
		return "Banned network"
	case CDropPanic:
		return "Overload breaker"
	case CDropMalformed:
		return "Broken packet"
	case CDropBogon:
		return "Impossible sender"
	case CDropPrivate:
		return "Private sender"
	case CDropTCPFlags:
		return "Bad TCP flags"
	case CDropFrag:
		return "Fragment"
	case CDropAmp:
		return "Amplified reply"
	case CDropReflect:
		return "Unasked-for reply"
	case CDropNewSrc:
		return "New-sender limit"
	case CDropToken:
		return "Token bucket"
	case CDropCap:
		return "Attack cap"
	case CDropRate:
		return "Rate ban"
	}
	return fmt.Sprintf("slot %d", slot)
}

// Reason bits in BanVal.Reason beyond the per-limit levels.
const (
	RManual uint32 = 1 << 16
	RSubnet uint32 = 1 << 17
)

// ReasonText turns a ban reason into words.
func ReasonText(reason uint32) string {
	if reason&RManual != 0 {
		return "added by hand"
	}
	if reason&RSubnet != 0 {
		return "many banned addresses in this network"
	}
	names := []string{"packets", "bytes", "TCP", "UDP", "ICMP", "new connections"}
	var parts []string
	for i, n := range names {
		level := (reason >> (2 * uint(i))) & 3
		if level == 0 {
			continue
		}
		times := []string{"", "over the limit", "2x over", "4x over"}[level]
		parts = append(parts, n+" "+times)
	}
	if len(parts) == 0 {
		return "repeated limit breaks"
	}
	return strings.Join(parts, ", ")
}

// KeyOf converts an address to the 16-byte form the kernel uses.
func KeyOf(a netip.Addr) AddrKey {
	return AddrKey{A: a.As16()}
}

// AddrOf converts a kernel key back to an address.
func AddrOf(k [16]byte) netip.Addr {
	return netip.AddrFrom16(k).Unmap()
}

// LpmOf converts a network to the kernel's longest-prefix key.
func LpmOf(p netip.Prefix) LpmKey {
	bits := p.Bits()
	if p.Addr().Is4() {
		bits += 96
	}
	return LpmKey{Prefixlen: uint32(bits), A: p.Masked().Addr().As16()}
}

// PrefixOf converts a kernel longest-prefix key back to a network.
func PrefixOf(k LpmKey) netip.Prefix {
	a := netip.AddrFrom16(k.A)
	bits := int(k.Prefixlen)
	if a.Is4In6() && bits >= 96 {
		return netip.PrefixFrom(a.Unmap(), bits-96)
	}
	return netip.PrefixFrom(a, bits)
}

// ParseTarget reads "1.2.3.4", "1.2.3.0/24" or the IPv6 forms.
func ParseTarget(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("%q is not a network", s)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is not an address", s)
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}
