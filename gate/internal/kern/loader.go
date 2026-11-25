package kern

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// PinDir is where the running gate leaves its maps for the command line.
const PinDir = "/sys/fs/bpf/sentrai-gate"

// MapNames are the maps a running gate pins.
var MapNames = []string{"cfg_map", "counters", "allow", "bans", "subnets", "ip_stats"}

// Options for Load.
type Options struct {
	MaxAddresses uint32 // ip_stats size, 0 = built-in
	MaxBans      uint32
	MaxLevel     int  // highest pipeline level to try (2 = everything)
	NoTrack      bool // do not load the outgoing-flow tracker
}

// Feature is one thing the kernel was asked for, and whether it is in use.
type Feature struct {
	Name string `json:"name"`
	On   bool   `json:"on"`
	Note string `json:"note"`
}

// Gate is a loaded (and maybe attached) filter.
type Gate struct {
	coll     *ebpf.Collection
	xdp      link.Link
	tcx      link.Link
	Level    int
	Events   bool
	Tracking bool
	Mode     string // "native" or "generic"
	Iface    string
	Features []Feature
}

// KernelVersion returns major, minor of the running kernel.
func KernelVersion() (int, int) {
	var u unix.Utsname
	if unix.Uname(&u) != nil {
		return 0, 0
	}
	rel := unix.ByteSliceToString(u.Release[:])
	parts := strings.SplitN(rel, ".", 3)
	if len(parts) < 2 {
		return 0, 0
	}
	major, _ := strconv.Atoi(parts[0])
	minor := 0
	for i, c := range parts[1] {
		if c < '0' || c > '9' {
			minor, _ = strconv.Atoi(parts[1][:i])
			break
		}
		if i == len(parts[1])-1 {
			minor, _ = strconv.Atoi(parts[1])
		}
	}
	return major, minor
}

// KernelRelease returns the kernel's own version text.
func KernelRelease() string {
	var u unix.Utsname
	if unix.Uname(&u) != nil {
		return "unknown"
	}
	return unix.ByteSliceToString(u.Release[:])
}

func atLeast(major, minor int) bool {
	a, b := KernelVersion()
	return a > major || (a == major && b >= minor)
}

// Probe reports what this kernel can do, without loading the filter.
func Probe() []Feature {
	var out []Feature
	add := func(name string, err error, missing string) bool {
		f := Feature{Name: name, On: err == nil}
		if err != nil {
			f.Note = missing
			if !errors.Is(err, ebpf.ErrNotSupported) {
				f.Note = missing + " (" + err.Error() + ")"
			}
		}
		out = append(out, f)
		return err == nil
	}
	add("Packet filter at the network card (XDP)", features.HaveProgramType(ebpf.XDP),
		"this kernel cannot run the gate at all")
	add("Network lists (allow list, banned networks)", features.HaveMapType(ebpf.LPMTrie),
		"this kernel cannot run the gate at all")
	add("Per-address memory that forgets the quietest first", features.HaveMapType(ebpf.LRUHash),
		"this kernel cannot run the gate at all")
	add("Instant ban notices", features.HaveMapType(ebpf.RingBuf),
		"bans are picked up by checking the ban list every second instead")
	var tcx error
	if !atLeast(6, 6) {
		tcx = ebpf.ErrNotSupported
	}
	add("Tracking of connections this machine starts", tcx,
		"needs kernel 6.6 or newer; replies are told apart by port numbers instead")
	return out
}

// Load puts the filter in the kernel, stepping down to a simpler pipeline
// when the kernel will not take the full one.
func Load(opts Options) (*Gate, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		// Only matters on kernels before 5.11; carry on and let the load say so.
		_ = err
	}
	g := &Gate{}

	events := features.HaveMapType(ebpf.RingBuf) == nil
	track := !opts.NoTrack && atLeast(6, 6)
	top := opts.MaxLevel
	if top < 0 || top > 2 {
		top = 2
	}

	var lastErr error
	for level := top; level >= 0; level-- {
		coll, err := tryLoad(opts, level, events, track)
		if err != nil && track {
			// Maybe only the tracker is the problem.
			if c2, err2 := tryLoad(opts, level, events, false); err2 == nil {
				coll, err, track = c2, nil, false
				g.note("Tracking of connections this machine starts", false,
					"the kernel refused the tracker; replies are told apart by port numbers instead")
			}
		}
		if err != nil {
			lastErr = err
			continue
		}
		g.coll, g.Level, g.Events, g.Tracking = coll, level, events, track
		break
	}
	if g.coll == nil {
		return nil, fmt.Errorf("the kernel refused the packet filter: %w", lastErr)
	}

	levelNote := ""
	switch g.Level {
	case 1:
		levelNote = "simpler pipeline: no reflection filter, token bucket, new-sender limit or breaker"
	case 0:
		levelNote = "core pipeline only: allow list, bans and packet checks"
	}
	g.note("Full pipeline", g.Level == 2, levelNote)
	if g.Level < top && lastErr != nil {
		g.note("Kernel message", false, firstLine(lastErr.Error()))
	}
	evNote := ""
	if !events {
		evNote = "bans are picked up by checking the ban list every second instead"
	}
	g.note("Instant ban notices", events, evNote)
	return g, nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 160 {
		s = s[:160]
	}
	return s
}

func (g *Gate) note(name string, on bool, note string) {
	for i := range g.Features {
		if g.Features[i].Name == name {
			g.Features[i] = Feature{name, on, note}
			return
		}
	}
	g.Features = append(g.Features, Feature{name, on, note})
}

func tryLoad(opts Options, level int, events, track bool) (*ebpf.Collection, error) {
	spec, err := loadGate()
	if err != nil {
		return nil, err
	}
	if err := spec.Variables["gate_level"].Set(uint32(level)); err != nil {
		return nil, err
	}
	ev := uint32(0)
	if events {
		ev = 1
	}
	if err := spec.Variables["gate_events"].Set(ev); err != nil {
		return nil, err
	}
	if !events {
		// The code that writes notices is gone; the map only has to exist.
		spec.Maps["events"] = &ebpf.MapSpec{Name: "events", Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1}
	}
	if !track {
		delete(spec.Programs, "gate_egress")
		spec.Maps["flows"].MaxEntries = 1
	}
	if opts.MaxAddresses > 0 {
		spec.Maps["ip_stats"].MaxEntries = opts.MaxAddresses
	}
	if opts.MaxBans > 0 {
		spec.Maps["bans"].MaxEntries = opts.MaxBans
	}
	return ebpf.NewCollection(spec)
}

// Map returns one of the filter's maps by name.
func (g *Gate) Map(name string) *ebpf.Map { return g.coll.Maps[name] }

// Ingress returns the XDP program (used by tests).
func (g *Gate) Ingress() *ebpf.Program { return g.coll.Programs["gate_ingress"] }

// Egress returns the tracker program, or nil when it is not loaded.
func (g *Gate) Egress() *ebpf.Program { return g.coll.Programs["gate_egress"] }

// Attach hooks the filter onto a network interface. mode is "auto",
// "native" or "generic".
func (g *Gate) Attach(iface, mode string) error {
	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		return fmt.Errorf("network interface %q: %w", iface, err)
	}
	try := func(flag link.XDPAttachFlags) (link.Link, error) {
		return link.AttachXDP(link.XDPOptions{Program: g.Ingress(), Interface: ifc.Index, Flags: flag})
	}
	switch mode {
	case "native", "driver":
		g.xdp, err = try(link.XDPDriverMode)
		g.Mode = "native"
	case "generic", "skb":
		g.xdp, err = try(link.XDPGenericMode)
		g.Mode = "generic"
	default:
		g.xdp, err = try(link.XDPDriverMode)
		g.Mode = "native"
		if err != nil {
			nativeErr := err
			g.xdp, err = try(link.XDPGenericMode)
			g.Mode = "generic"
			if err == nil {
				g.note("Fastest mode (inside the network card driver)", false,
					"this card's driver does not offer it ("+firstLine(nativeErr.Error())+"); using the kernel's general mode, which still runs before the firewall and the apps")
			}
		}
	}
	if err != nil {
		return fmt.Errorf("could not attach to %s: %w", iface, err)
	}
	if g.Mode == "native" {
		g.note("Fastest mode (inside the network card driver)", true, "")
	}
	g.Iface = iface

	if g.Tracking && g.Egress() != nil {
		g.tcx, err = link.AttachTCX(link.TCXOptions{Interface: ifc.Index, Program: g.Egress(), Attach: ebpf.AttachTCXEgress})
		if err != nil {
			g.Tracking = false
			g.note("Tracking of connections this machine starts", false,
				"could not attach ("+firstLine(err.Error())+"); replies are told apart by port numbers instead")
		} else {
			g.note("Tracking of connections this machine starts", true, "")
		}
	} else {
		g.Tracking = false
		g.note("Tracking of connections this machine starts", false,
			"needs kernel 6.6 or newer; replies are told apart by port numbers instead")
	}
	return nil
}

// Pin leaves the maps where the command line can find them.
func (g *Gate) Pin() error {
	if !BPFFSMounted() {
		// Minimal systems and containers do not always mount it.
		_ = os.MkdirAll("/sys/fs/bpf", 0o755)
		_ = unix.Mount("bpf", "/sys/fs/bpf", "bpf", 0, "")
	}
	if err := os.MkdirAll(PinDir, 0o700); err != nil {
		return fmt.Errorf("%s: %w (is the BPF file system mounted at /sys/fs/bpf?)", PinDir, err)
	}
	for _, name := range MapNames {
		path := filepath.Join(PinDir, name)
		_ = os.Remove(path)
		if err := g.coll.Maps[name].Pin(path); err != nil {
			return fmt.Errorf("pin %s: %w", name, err)
		}
	}
	return nil
}

// BPFFSMounted says whether the BPF file system is at /sys/fs/bpf.
func BPFFSMounted() bool {
	var fs unix.Statfs_t
	return unix.Statfs("/sys/fs/bpf", &fs) == nil && fs.Type == unix.BPF_FS_MAGIC
}

// Close detaches the filter and removes its pins. Traffic then flows as if
// the gate was never there.
func (g *Gate) Close() {
	if g.tcx != nil {
		g.tcx.Close()
	}
	if g.xdp != nil {
		g.xdp.Close()
	}
	if g.coll != nil {
		for _, name := range MapNames {
			if m := g.coll.Maps[name]; m != nil && m.IsPinned() {
				_ = m.Unpin()
			}
		}
		g.coll.Close()
	}
	_ = os.Remove(PinDir)
}

// OpenPinned opens a running gate's map from the command line.
func OpenPinned(name string) (*ebpf.Map, error) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(PinDir, name), nil)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("the gate is not running")
		}
		if errors.Is(err, os.ErrPermission) {
			return nil, errors.New("this needs root. Run it again with sudo")
		}
		return nil, err
	}
	return m, nil
}

// Running says whether a gate has its maps pinned.
func Running() bool {
	_, err := os.Stat(filepath.Join(PinDir, "cfg_map"))
	return err == nil
}

// Now returns the kernel clock the filter stamps bans with, in ns.
func Now() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
}

// ReadCounters sums the per-CPU counters.
func ReadCounters(m *ebpf.Map) ([CMax]Ctr, error) {
	var out [CMax]Ctr
	for slot := uint32(0); slot < CMax; slot++ {
		var per []Ctr
		if err := m.Lookup(slot, &per); err != nil {
			return out, err
		}
		for _, c := range per {
			out[slot].Pkts += c.Pkts
			out[slot].Bytes += c.Bytes
		}
	}
	return out, nil
}
