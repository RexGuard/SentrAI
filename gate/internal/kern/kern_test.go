package kern

import (
	"encoding/binary"
	"net/netip"
	"os"
	"testing"
	"time"
)

// These tests load the real filter into the kernel and feed it hand-made
// packets through the kernel's own test hook. They need root.

const (
	xdpDrop = 1
	xdpPass = 2
)

func load(t *testing.T, level int) *Gate {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root to load the packet filter")
	}
	g, err := Load(Options{MaxLevel: level})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	t.Cleanup(g.Close)
	return g
}

func baseCfg() Cfg {
	c := Cfg{
		Flags: FEnabled | FDropBogon | FDropBadTCP | FAmp | FRate | FPanic | FNewSrc,
		Pps:   1000, Bps: 10 << 20, TcpPps: 800, UdpPps: 500, IcmpPps: 50, SynPps: 100,
		S_pps: 20, S_bps: 20, S_tcp: 15, S_udp: 15, S_icmp: 25, S_syn: 30,
		ScoreBan: 100, ScoreDecay: 10, BanSecs: 600,
		StrikeMult: [8]uint32{1, 2, 4, 8, 16, 32, 32, 32},
		AttackPct:  50, AttackIpPps: 300, NewsrcLimit: 50,
	}
	c.AmpPort[0], c.AmpMin[0] = 53, 1233
	c.AmpPort[1], c.AmpMin[1] = 123, 200
	return c
}

func setCfg(t *testing.T, g *Gate, c Cfg) {
	t.Helper()
	if err := g.Map("cfg_map").Put(uint32(0), &c); err != nil {
		t.Fatalf("set config: %v", err)
	}
}

type pktSpec struct {
	src, dst     string
	proto        uint8
	sport, dport uint16
	flags        uint8
	payload      int
	fragOff      uint16 // raw frag_off field
	dnsReply     bool
}

func build(p pktSpec) []byte {
	src, dst := netip.MustParseAddr(p.src), netip.MustParseAddr(p.dst)
	eth := make([]byte, 14)
	var l4 []byte
	switch p.proto {
	case 6:
		l4 = make([]byte, 20+p.payload)
		binary.BigEndian.PutUint16(l4[0:], p.sport)
		binary.BigEndian.PutUint16(l4[2:], p.dport)
		l4[12] = 5 << 4
		l4[13] = p.flags
	case 17:
		l4 = make([]byte, 8+p.payload)
		binary.BigEndian.PutUint16(l4[0:], p.sport)
		binary.BigEndian.PutUint16(l4[2:], p.dport)
		binary.BigEndian.PutUint16(l4[4:], uint16(8+p.payload))
		if p.dnsReply && p.payload >= 3 {
			l4[8+2] = 0x80
		}
	default:
		l4 = make([]byte, 8+p.payload)
	}
	if src.Is4() {
		binary.BigEndian.PutUint16(eth[12:], 0x0800)
		ip := make([]byte, 20)
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:], uint16(20+len(l4)))
		binary.BigEndian.PutUint16(ip[6:], p.fragOff)
		ip[8] = 64
		ip[9] = p.proto
		s, d := src.As4(), dst.As4()
		copy(ip[12:], s[:])
		copy(ip[16:], d[:])
		return append(append(eth, ip...), l4...)
	}
	binary.BigEndian.PutUint16(eth[12:], 0x86DD)
	ip := make([]byte, 40)
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:], uint16(len(l4)))
	ip[6] = p.proto
	ip[7] = 64
	s, d := src.As16(), dst.As16()
	copy(ip[8:], s[:])
	copy(ip[24:], d[:])
	return append(append(eth, ip...), l4...)
}

func run(t *testing.T, g *Gate, p pktSpec) uint32 {
	t.Helper()
	ret, _, err := g.Ingress().Test(build(p))
	if err != nil {
		t.Fatalf("run packet: %v", err)
	}
	return ret
}

func want(t *testing.T, g *Gate, what string, p pktSpec, verdict uint32) {
	t.Helper()
	if got := run(t, g, p); got != verdict {
		t.Errorf("%s: got verdict %d, want %d", what, got, verdict)
	}
}

func counter(t *testing.T, g *Gate, slot int) uint64 {
	t.Helper()
	c, err := ReadCounters(g.Map("counters"))
	if err != nil {
		t.Fatal(err)
	}
	return c[slot].Pkts
}

const me = "203.0.114.10"

func syn(src string) pktSpec {
	return pktSpec{src: src, dst: me, proto: 6, sport: 40000, dport: 443, flags: 0x02}
}

func TestNoConfigPassesEverything(t *testing.T) {
	g := load(t, 2)
	want(t, g, "no settings", pktSpec{src: "127.0.0.1", dst: me, proto: 6, flags: 0x03}, xdpPass)
}

func TestChecks(t *testing.T) {
	g := load(t, 2)
	setCfg(t, g, baseCfg())

	want(t, g, "ordinary new connection", syn("8.8.8.8"), xdpPass)
	want(t, g, "loopback sender", syn("127.0.0.1"), xdpDrop)
	want(t, g, "multicast sender", syn("224.0.0.5"), xdpDrop)
	want(t, g, "documentation range sender", syn("192.0.2.9"), xdpDrop)
	want(t, g, "private sender allowed by default", syn("10.1.2.3"), xdpPass)
	want(t, g, "cloud metadata sender", syn("169.254.169.254"), xdpPass)

	bad := syn("8.8.4.4")
	bad.flags = 0x03 // SYN+FIN
	want(t, g, "SYN+FIN", bad, xdpDrop)
	bad.flags = 0
	want(t, g, "no flags", bad, xdpDrop)
	bad.flags = 0x29 // FIN+PSH+URG
	want(t, g, "xmas", bad, xdpDrop)

	want(t, g, "IPv6 connection", syn("2001:4860:4860::8888"), xdpPass)
	want(t, g, "IPv6 multicast sender", syn("ff02::1"), xdpDrop)
	want(t, g, "IPv4 dressed as IPv6", syn("::ffff:8.8.8.8"), xdpDrop)

	short := build(syn("8.8.8.8"))[:20]
	if ret, _, err := g.Ingress().Test(short); err != nil || ret != xdpDrop {
		t.Errorf("cut-off packet: verdict %d err %v, want drop", ret, err)
	}

	arp := make([]byte, 42)
	binary.BigEndian.PutUint16(arp[12:], 0x0806)
	if ret, _, _ := g.Ingress().Test(arp); ret != xdpPass {
		t.Errorf("ARP must always pass, got %d", ret)
	}

	c := baseCfg()
	c.Flags |= FDropPrivate | FDropFrags
	setCfg(t, g, c)
	want(t, g, "private sender when asked to drop", syn("10.1.2.3"), xdpDrop)
	frag := pktSpec{src: "9.9.9.9", dst: me, proto: 17, sport: 5000, dport: 5000, fragOff: 0x2000}
	want(t, g, "fragment when asked to drop", frag, xdpDrop)
}

func TestAllowAndBanLists(t *testing.T) {
	g := load(t, 2)
	c := baseCfg()
	c.Flags |= FHasAllow | FHasSubnets
	setCfg(t, g, c)

	one := uint32(1)
	if err := g.Map("allow").Put(LpmOf(netip.MustParsePrefix("127.0.0.0/8")), one); err != nil {
		t.Fatal(err)
	}
	want(t, g, "allow list beats the checks", syn("127.0.0.1"), xdpPass)

	ban := func(addr string, until uint64) {
		k := KeyOf(netip.MustParseAddr(addr))
		if err := g.Map("bans").Put(k, BanVal{Until: until, Reason: RManual}); err != nil {
			t.Fatal(err)
		}
	}
	ban("1.2.3.4", 0)
	want(t, g, "banned for good", syn("1.2.3.4"), xdpDrop)
	ban("1.2.3.5", Now()+60e9)
	want(t, g, "banned for a minute", syn("1.2.3.5"), xdpDrop)
	ban("1.2.3.6", 1)
	want(t, g, "ban that has run out", syn("1.2.3.6"), xdpPass)
	var v BanVal
	if err := g.Map("bans").Lookup(KeyOf(netip.MustParseAddr("1.2.3.6")), &v); err == nil {
		t.Error("a ban that ran out should be removed by the kernel")
	}

	if err := g.Map("subnets").Put(LpmOf(netip.MustParsePrefix("5.6.7.0/24")), BanVal{}); err != nil {
		t.Fatal(err)
	}
	want(t, g, "inside a banned network", syn("5.6.7.200"), xdpDrop)
	want(t, g, "next to a banned network", syn("5.6.8.1"), xdpPass)

	if err := g.Map("subnets").Put(LpmOf(netip.MustParsePrefix("2001:db8::/32")), BanVal{}); err != nil {
		t.Fatal(err)
	}
	want(t, g, "inside a banned IPv6 network", syn("2001:db8::5"), xdpDrop)
}

func TestFloodGetsBanned(t *testing.T) {
	g := load(t, 2)
	setCfg(t, g, baseCfg())

	flood := syn("45.0.0.7")
	dropped := 0
	for i := 0; i < 2000; i++ {
		if run(t, g, flood) == xdpDrop {
			dropped++
		}
	}
	if dropped < 1000 {
		t.Errorf("a 2000-packet connection flood should be mostly dropped, dropped %d", dropped)
	}
	var v BanVal
	if err := g.Map("bans").Lookup(KeyOf(netip.MustParseAddr("45.0.0.7")), &v); err != nil {
		t.Fatalf("flooder is not on the ban list: %v", err)
	}
	if v.Strikes != 1 || v.Until <= Now() {
		t.Errorf("ban = %+v, want first strike with a future end", v)
	}
	if n := counter(t, g, CNewBan); n != 1 {
		t.Errorf("new-ban counter = %d, want 1", n)
	}
	want(t, g, "a quiet neighbour is untouched", syn("45.0.0.8"), xdpPass)

	// A normal visitor well under the limits is never banned.
	for i := 0; i < 90; i++ {
		want(t, g, "normal visitor", syn("45.0.0.9"), xdpPass)
	}
}

func TestObserveModeDropsNothing(t *testing.T) {
	g := load(t, 2)
	c := baseCfg()
	c.Flags |= FObserve
	setCfg(t, g, c)
	want(t, g, "observe: bad sender still passes", syn("127.0.0.1"), xdpPass)
	if counter(t, g, CWouldDrop) != 1 || counter(t, g, CDropBogon) != 1 {
		t.Error("observe mode should still count what it would have dropped")
	}
}

func TestReflection(t *testing.T) {
	g := load(t, 2)
	setCfg(t, g, baseCfg())

	big := pktSpec{src: "8.8.8.8", dst: me, proto: 17, sport: 53, dport: 41000, payload: 1400, dnsReply: true}
	small := big
	small.payload = 120
	want(t, g, "huge DNS answer nobody asked for", big, xdpDrop)
	want(t, g, "small DNS answer (no tracking: benefit of the doubt)", small, xdpPass)
	ntp := pktSpec{src: "7.7.7.7", dst: me, proto: 17, sport: 123, dport: 123, payload: 440}
	want(t, g, "oversized time-server answer", ntp, xdpDrop)
	ntp.payload = 48
	want(t, g, "normal time-server answer", ntp, xdpPass)

	if g.Egress() == nil {
		t.Skip("no tracker on this kernel")
	}
	c := baseCfg()
	c.Flags |= FTrack | FReflect
	setCfg(t, g, c)

	want(t, g, "tracked: small DNS answer nobody asked for", small, xdpDrop)
	synack := pktSpec{src: "93.184.216.34", dst: me, proto: 6, sport: 443, dport: 50123, flags: 0x12}
	want(t, g, "tracked: reply to a call we never made", synack, xdpDrop)

	out := func(p pktSpec) {
		t.Helper()
		if _, _, err := g.Egress().Test(build(p)); err != nil {
			t.Fatalf("run outgoing packet: %v", err)
		}
	}
	out(pktSpec{src: me, dst: "8.8.8.8", proto: 17, sport: 41000, dport: 53, payload: 40})
	out(pktSpec{src: me, dst: "93.184.216.34", proto: 6, sport: 50123, dport: 443, flags: 0x02})
	want(t, g, "tracked: DNS answer we asked for", big, xdpPass)
	want(t, g, "tracked: reply to our own call", synack, xdpPass)

	// A big download we started must not get the far end banned.
	data := pktSpec{src: "93.184.216.34", dst: me, proto: 6, sport: 443, dport: 50123, flags: 0x10, payload: 1400}
	for round := 0; round < 3; round++ {
		for i := 0; i < 5000; i++ {
			if run(t, g, data) != xdpPass {
				t.Fatalf("download packet %d of second %d was dropped", i, round)
			}
		}
		time.Sleep(1100 * time.Millisecond) // into the next one-second window
	}
	var v BanVal
	if g.Map("bans").Lookup(KeyOf(netip.MustParseAddr("93.184.216.34")), &v) == nil {
		t.Error("the far end of our own download was banned")
	}
}

func TestSlowFloodIsCaughtOverSeveralSeconds(t *testing.T) {
	g := load(t, 2)
	setCfg(t, g, baseCfg())
	// 150 new connections a second against a limit of 100: under the
	// every-256-packets check, so only the end-of-second check sees it.
	addr := netip.MustParseAddr("46.0.0.1")
	var v BanVal
	for sec := 0; sec < 6; sec++ {
		for i := 0; i < 150; i++ {
			run(t, g, syn(addr.String()))
		}
		time.Sleep(1050 * time.Millisecond)
		if g.Map("bans").Lookup(KeyOf(addr), &v) == nil {
			if sec < 2 {
				t.Errorf("banned after only %d seconds: one bad second should be a warning", sec+1)
			}
			return
		}
	}
	t.Error("a steady flood just over the limit was never banned")
}

func TestScoreIsForgivenAfterQuietTime(t *testing.T) {
	g := load(t, 2)
	setCfg(t, g, baseCfg())
	addr := netip.MustParseAddr("47.0.0.1")
	burst := func() {
		for i := 0; i < 150; i++ {
			run(t, g, syn(addr.String()))
		}
	}
	// One bad second, then quiet, again and again: never adds up to a ban.
	for i := 0; i < 3; i++ {
		burst()
		time.Sleep(4100 * time.Millisecond)
	}
	run(t, g, syn(addr.String()))
	var v BanVal
	if g.Map("bans").Lookup(KeyOf(addr), &v) == nil {
		t.Error("short bursts with quiet time between them should be forgiven")
	}
}

func TestAttackModeTightens(t *testing.T) {
	g := load(t, 2)
	c := baseCfg()
	c.Flags |= FAttack
	setCfg(t, g, c)

	// 300 packets a second per address is the hard cap while under attack.
	udp := pktSpec{src: "60.0.0.1", dst: me, proto: 17, sport: 9000, dport: 9000, payload: 10}
	passed := 0
	for i := 0; i < 400; i++ {
		if run(t, g, udp) == xdpPass {
			passed++
		}
	}
	if passed > 300 {
		t.Errorf("attack cap let %d of 400 through, want at most 300", passed)
	}
	if counter(t, g, CDropCap) == 0 {
		t.Error("attack cap never fired")
	}

	// Forged-looking stream of never-seen senders: only the first 50 a
	// second get in (per CPU; the test runs on one).
	before := counter(t, g, CDropNewSrc)
	for i := 0; i < 200; i++ {
		a := netip.AddrFrom4([4]byte{70, 1, byte(i >> 8), byte(i)})
		run(t, g, syn(a.String()))
	}
	if counter(t, g, CDropNewSrc)-before < 100 {
		t.Error("new-sender limit did not hold back a stream of forged senders")
	}
}

func TestTokenBucket(t *testing.T) {
	g := load(t, 2)
	c := baseCfg()
	c.Flags |= FToken
	c.TokenRate, c.TokenBurst = 10, 20
	setCfg(t, g, c)
	p := pktSpec{src: "80.0.0.1", dst: me, proto: 17, sport: 1, dport: 2, payload: 10}
	passed := 0
	for i := 0; i < 100; i++ {
		if run(t, g, p) == xdpPass {
			passed++
		}
	}
	if passed < 20 || passed > 25 {
		t.Errorf("token bucket let %d through, want about 20", passed)
	}
}

func TestSimplerPipelinesLoad(t *testing.T) {
	for _, level := range []int{1, 0} {
		g := load(t, level)
		if g.Level != level {
			t.Errorf("asked for level %d, got %d", level, g.Level)
		}
		setCfg(t, g, baseCfg())
		want(t, g, "ordinary connection", syn("8.8.8.8"), xdpPass)
		want(t, g, "loopback sender", syn("127.0.0.1"), xdpDrop)
	}
}

func TestKeys(t *testing.T) {
	p, err := ParseTarget("10.2.3.4/16")
	if err != nil || p.String() != "10.2.0.0/16" {
		t.Fatalf("ParseTarget = %v, %v", p, err)
	}
	if got := PrefixOf(LpmOf(p)); got != p {
		t.Errorf("round trip = %v", got)
	}
	p6 := netip.MustParsePrefix("2001:db8::/48")
	if got := PrefixOf(LpmOf(p6)); got != p6 {
		t.Errorf("IPv6 round trip = %v", got)
	}
	a := netip.MustParseAddr("1.2.3.4")
	if got := AddrOf(KeyOf(a).A); got != a {
		t.Errorf("address round trip = %v", got)
	}
	if _, err := ParseTarget("nonsense"); err == nil {
		t.Error("nonsense should not parse")
	}
}
