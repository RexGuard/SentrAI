package engine

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/RexGuard/SentrAI/gate/internal/config"
	"github.com/RexGuard/SentrAI/gate/internal/kern"
)

// Version is set at build time.
var Version = "dev"

const (
	historyLen = 300
	eventsLen  = 100
	attacksLen = 20
)

// Engine is one running gate.
type Engine struct {
	ConfigPath string
	Log        func(format string, a ...any)

	cfg  *config.Config
	gate *kern.Gate
	det  *Detector

	started   time.Time
	prev      [kern.CMax]kern.Ctr
	prevAt    time.Time
	history   []Point
	events    []EventRow
	attacks   []AttackRow
	attackBan int
	peakPPS   float64
	peakBPS   float64
	problems  []string

	bans      []BanRow
	banCount  int
	netCount  int
	allowN    int
	busiest   []Talker
	known     map[kern.AddrKey]bool
	hasAllow  bool
	hasSubnet bool
	pushed    kern.Cfg
	evCh      chan kern.Event
	tickN     int
}

type savedState struct {
	SavedAt  time.Time   `json:"saved_at"`
	Detector *Detector   `json:"normal"`
	Bans     []savedBan  `json:"bans"`
	Networks []savedBan  `json:"networks"`
	Attacks  []AttackRow `json:"attacks"`
}

type savedBan struct {
	Target  string `json:"target"`
	Until   int64  `json:"until"` // unix seconds, 0 = until removed
	Reason  uint32 `json:"reason"`
	Strikes uint32 `json:"strikes"`
}

func (e *Engine) logf(format string, a ...any) {
	if e.Log != nil {
		e.Log(format, a...)
	}
}

// Run loads the filter, attaches it and looks after it until ctx ends or
// the process is told to stop. When it returns the filter is gone and
// traffic flows untouched.
func (e *Engine) Run(ctx context.Context) error {
	cfg, err := config.Load(e.ConfigPath)
	if err != nil {
		return err
	}
	if cfg.Interface == "" {
		return errors.New("settings problem: interface is not set")
	}
	e.cfg = cfg
	e.det = NewDetector(cfg.Attack)
	e.known = map[kern.AddrKey]bool{}
	e.started = time.Now()

	for _, d := range []string{config.RunDir, config.StateDir, config.LogDir} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			return err
		}
	}
	// Anyone on the machine may read the status; only root changes things.
	_ = os.Chmod(config.RunDir, 0o755)

	gate, err := kern.Load(kern.Options{MaxAddresses: cfg.Sizes.Addresses, MaxBans: cfg.Sizes.Bans, MaxLevel: 2})
	if err != nil {
		return err
	}
	e.gate = gate
	defer func() {
		e.save()
		gate.Close()
		_ = os.Remove(StatusFile)
		_ = os.Remove(PidFile)
	}()

	// Lists and saved bans go in before the filter sees its first packet.
	e.restore()
	e.syncLists()
	if err := gate.Attach(cfg.Interface, cfg.Mode); err != nil {
		return err
	}
	if err := gate.Pin(); err != nil {
		return err
	}
	e.push(true)
	_ = config.WriteFile(PidFile, []byte(strconv.Itoa(os.Getpid())), 0o644)

	if gate.Events {
		rd, err := ringbuf.NewReader(gate.Map("events"))
		if err == nil {
			e.evCh = make(chan kern.Event, 1024)
			go readEvents(rd, e.evCh)
			defer rd.Close()
		} else {
			gate.Events = false
		}
	}

	what := "guarding"
	if cfg.Observe {
		what = "watching only (observe mode), dropping nothing on"
	}
	e.event("start", "", fmt.Sprintf("SentrAI Gate %s %s %s in %s mode, profile %s / %s",
		Version, what, cfg.Interface, gate.Mode, cfg.Profile, cfg.Level))
	for _, f := range gate.Features {
		if !f.On {
			e.logf("not available: %s. %s", f.Name, f.Note)
		}
	}

	sig := make(chan os.Signal, 4)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sig)

	e.prev, _ = kern.ReadCounters(gate.Map("counters"))
	e.prevAt = time.Now()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			e.event("stop", "", "SentrAI Gate stopped. Traffic is no longer filtered")
			return nil
		case s := <-sig:
			if s == syscall.SIGHUP {
				e.reload()
				continue
			}
			e.event("stop", "", "SentrAI Gate stopped. Traffic is no longer filtered")
			return nil
		case now := <-tick.C:
			e.tick(now)
		}
	}
}

func readEvents(rd *ringbuf.Reader, out chan<- kern.Event) {
	for {
		rec, err := rd.Read()
		if err != nil {
			close(out)
			return
		}
		var ev kern.Event
		if binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ev) == nil {
			select {
			case out <- ev:
			default: // a flood of bans: the list scan still finds them
			}
		}
	}
}

func (e *Engine) reload() {
	cfg, err := config.Load(e.ConfigPath)
	if err != nil {
		e.event("reload", "", "Settings not reloaded, the old ones stay in use: "+err.Error())
		return
	}
	note := ""
	if cfg.Interface != e.cfg.Interface || cfg.Mode != e.cfg.Mode || cfg.Sizes != e.cfg.Sizes {
		note = " (interface, mode and sizes need a restart: sudo systemctl restart sentrai-gate)"
		cfg.Interface, cfg.Mode, cfg.Sizes = e.cfg.Interface, e.cfg.Mode, e.cfg.Sizes
	}
	e.cfg = cfg
	e.det.SetConfig(cfg.Attack)
	e.syncLists()
	e.push(true)
	e.event("reload", "", "Settings and lists reloaded"+note)
}

// push writes the settings the kernel filter reads, when they changed.
func (e *Engine) push(force bool) {
	k := e.cfg.Kernel(e.hasAllow, e.hasSubnet, e.gate.Tracking, e.det.Active)
	if !force && k == e.pushed {
		return
	}
	if err := e.gate.Map("cfg_map").Put(uint32(0), &k); err != nil {
		e.logf("could not update the filter settings: %v", err)
		return
	}
	e.pushed = k
}

// syncLists makes the kernel's allow list and permanent block list match
// the two list files.
func (e *Engine) syncLists() {
	e.problems = nil
	allow, probs, err := config.ReadList(config.AllowFile)
	if err != nil {
		probs = append(probs, err.Error())
	}
	e.problems = append(e.problems, probs...)
	block, probs, err := config.ReadList(config.BlockFile)
	if err != nil {
		probs = append(probs, err.Error())
	}
	e.problems = append(e.problems, probs...)

	am := e.gate.Map("allow")
	want := map[kern.LpmKey]bool{}
	for _, en := range allow {
		want[kern.LpmOf(en.Net)] = true
	}
	var k kern.LpmKey
	var v uint32
	var stale []kern.LpmKey
	it := am.Iterate()
	for it.Next(&k, &v) {
		if !want[k] {
			stale = append(stale, k)
		}
	}
	for _, k := range stale {
		_ = am.Delete(k)
	}
	for k := range want {
		if err := am.Put(k, uint32(1)); err != nil {
			e.problems = append(e.problems, "allow list is full: "+kern.PrefixOf(k).String()+" was not added")
		}
	}
	e.allowN = len(want)

	sm := e.gate.Map("subnets")
	wantB := map[kern.LpmKey]bool{}
	for _, en := range block {
		wantB[kern.LpmOf(en.Net)] = true
	}
	var bv kern.BanVal
	stale = stale[:0]
	it = sm.Iterate()
	for it.Next(&k, &bv) {
		if bv.Reason&kern.RManual != 0 && bv.Until == 0 && !wantB[k] {
			stale = append(stale, k)
		}
	}
	for _, k := range stale {
		_ = sm.Delete(k)
	}
	for k := range wantB {
		if err := sm.Put(k, kern.BanVal{Reason: kern.RManual}); err != nil {
			e.problems = append(e.problems, "block list is full: "+kern.PrefixOf(k).String()+" was not added")
		}
	}
	e.hasAllow = len(want) > 0
	e.hasSubnet = len(wantB) > 0 || e.hasSubnet
}

func nonEmpty(m *ebpf.Map) bool {
	var k kern.LpmKey
	return m.NextKey(nil, &k) == nil
}

func (e *Engine) event(kind, target, text string) {
	row := EventRow{Time: time.Now(), Kind: kind, Target: target, Text: text}
	e.events = append(e.events, row)
	if len(e.events) > eventsLen {
		e.events = e.events[len(e.events)-eventsLen:]
	}
	e.logf("%s", text)
	appendLog(filepath.Join(config.LogDir, "events.log"), row)
}

func appendLog(path string, row any) {
	if st, err := os.Stat(path); err == nil && st.Size() > 20<<20 {
		_ = os.Rename(path, path+".1")
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return
	}
	defer f.Close()
	line, _ := json.Marshal(row)
	_, _ = f.Write(append(line, '\n'))
}

func rate(now, before uint64, secs float64) float64 {
	if now < before || secs <= 0 {
		return 0
	}
	return float64(now-before) / secs
}

func (e *Engine) tick(now time.Time) {
	e.tickN++
	cur, err := kern.ReadCounters(e.gate.Map("counters"))
	if err != nil {
		e.logf("could not read counters: %v", err)
		return
	}
	secs := now.Sub(e.prevAt).Seconds()
	r := func(slot int) float64 { return rate(cur[slot].Pkts, e.prev[slot].Pkts, secs) }
	s := Sample{
		PPS: r(kern.CSeen), BPS: rate(cur[kern.CSeen].Bytes, e.prev[kern.CSeen].Bytes, secs),
		TCP: r(kern.CTCP), UDP: r(kern.CUDP), ICMP: r(kern.CICMP), SYN: r(kern.CSYN),
		AmpDrops: r(kern.CDropAmp) + r(kern.CDropReflect), NewSenders: r(kern.CNewSrc),
	}
	for _, slot := range kern.DropSlots {
		s.DropPPS += r(slot)
		s.DropBPS += rate(cur[slot].Bytes, e.prev[slot].Bytes, secs)
	}
	e.prev, e.prevAt = cur, now

	if s.PPS > e.peakPPS {
		e.peakPPS = s.PPS
	}
	if s.BPS > e.peakBPS {
		e.peakBPS = s.BPS
	}
	e.history = append(e.history, Point{s.PPS, s.BPS, s.DropPPS})
	if len(e.history) > historyLen {
		e.history = e.history[len(e.history)-historyLen:]
	}

	started, ended := e.det.Tick(s, now)
	if started {
		e.attackBan = 0
		e.event("attack_start", "", fmt.Sprintf("Under attack: %s. %s packets a second against a normal %s. Limits tightened",
			e.det.Kind, human(s.PPS), human(e.det.Mean)))
	}
	if ended {
		row := AttackRow{Start: e.det.Since, End: now, Kind: e.det.Kind, PeakPPS: e.det.PeakPPS,
			PeakBPS: e.det.PeakBPS, Dropped: e.det.Dropped, Bans: e.attackBan}
		e.attacks = append(e.attacks, row)
		if len(e.attacks) > attacksLen {
			e.attacks = e.attacks[len(e.attacks)-attacksLen:]
		}
		appendLog(filepath.Join(config.LogDir, "attacks.log"), row)
		e.event("attack_end", "", fmt.Sprintf("Attack over after %s: %s, peak %s packets a second, %s packets dropped, %d addresses banned. Limits back to normal",
			now.Sub(row.Start).Round(time.Second), row.Kind, human(row.PeakPPS), human(row.Dropped), row.Bans))
	}

	e.drainEvents()

	// The command line can add to the lists directly, so look every second.
	e.hasAllow = nonEmpty(e.gate.Map("allow"))
	e.hasSubnet = nonEmpty(e.gate.Map("subnets"))
	if e.tickN%5 == 1 || started || ended {
		e.scanBans(now)
		e.scanBusiest()
	}
	if e.tickN%60 == 0 {
		e.save()
	}
	e.push(false)
	e.writeStatus(now, s, cur)
}

func (e *Engine) drainEvents() {
	if e.evCh == nil {
		return
	}
	for i := 0; i < 500; i++ {
		select {
		case ev, ok := <-e.evCh:
			if !ok {
				e.evCh = nil
				return
			}
			e.known[kern.AddrKey{A: ev.A}] = true
			e.banEvent(kern.AddrOf(ev.A), ev.Reason, ev.Strikes, time.Duration(ev.BanSecs)*time.Second,
				fmt.Sprintf(" (%d packets, %d new connections in under a second)", ev.Pkts, ev.Syn))
		default:
			return
		}
	}
}

func (e *Engine) banEvent(addr netip.Addr, reason, strikes uint32, length time.Duration, detail string) {
	e.attackBan++
	again := ""
	if strikes > 1 {
		again = fmt.Sprintf(", strike %d", strikes)
	}
	e.event("ban", addr.String(), fmt.Sprintf("Banned %s for %s%s: %s%s",
		addr, length.Round(time.Second), again, kern.ReasonText(reason), detail))
}

// scanBans walks the ban lists: removes what has run out, notices new
// bans, and bans a whole network when enough of it is banned.
func (e *Engine) scanBans(now time.Time) {
	kNow := kern.Now()
	wall := func(until uint64) time.Time {
		if until == 0 {
			return time.Time{}
		}
		return now.Add(time.Duration(int64(until) - int64(kNow)))
	}

	bm := e.gate.Map("bans")
	var k kern.AddrKey
	var v kern.BanVal
	var expired []kern.AddrKey
	var rows []BanRow
	perNet := map[netip.Prefix]int{}
	live := map[kern.AddrKey]bool{}
	count := 0
	an := e.cfg.Bans.AutoNetwork

	it := bm.Iterate()
	for it.Next(&k, &v) {
		if v.Until != 0 && v.Until <= kNow {
			expired = append(expired, k)
			continue
		}
		count++
		live[k] = true
		addr := kern.AddrOf(k.A)
		if !e.known[k] {
			e.known[k] = true
			if v.Reason&kern.RManual != 0 {
				e.event("ban", addr.String(), fmt.Sprintf("Banned %s by hand, %s", addr, leftText(wall(v.Until).Sub(now), v.Until == 0)))
			} else if e.evCh == nil {
				e.banEvent(addr, v.Reason, v.Strikes, wall(v.Until).Sub(now), "")
			}
		}
		if an.Enabled && addr.Is4() && v.Reason&kern.RManual == 0 {
			if p, err := addr.Prefix(an.Prefix); err == nil {
				perNet[p]++
			}
		}
		if len(rows) < 2000 {
			rows = append(rows, BanRow{Target: addr.String(), Until: wall(v.Until), Forever: v.Until == 0,
				Reason: kern.ReasonText(v.Reason), Strikes: v.Strikes})
		}
	}
	for _, k := range expired {
		_ = bm.Delete(k)
	}
	for k := range e.known {
		if !live[k] {
			delete(e.known, k)
		}
	}

	sm := e.gate.Map("subnets")
	var lk kern.LpmKey
	var expiredNets []kern.LpmKey
	haveNet := map[netip.Prefix]bool{}
	nets := 0
	it = sm.Iterate()
	for it.Next(&lk, &v) {
		if v.Until != 0 && v.Until <= kNow {
			expiredNets = append(expiredNets, lk)
			continue
		}
		nets++
		p := kern.PrefixOf(lk)
		haveNet[p] = true
		target := p.String()
		if p.IsSingleIP() {
			target = p.Addr().String()
		}
		rows = append(rows, BanRow{Target: target, Until: wall(v.Until), Forever: v.Until == 0, Reason: kern.ReasonText(v.Reason)})
	}
	for _, lk := range expiredNets {
		_ = sm.Delete(lk)
	}

	for p, n := range perNet {
		if n < an.After || haveNet[p] {
			continue
		}
		until := kNow + uint64(an.Seconds)*1e9
		if err := sm.Put(kern.LpmOf(p), kern.BanVal{Until: until, Reason: kern.RSubnet}); err == nil {
			nets++
			e.hasSubnet = true
			rows = append(rows, BanRow{Target: p.String(), Until: wall(until), Reason: kern.ReasonText(kern.RSubnet)})
			e.event("network_ban", p.String(), fmt.Sprintf("Banned the whole network %s for %s: %d of its addresses were already banned",
				p, (time.Duration(an.Seconds)*time.Second).Round(time.Second), n))
		}
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Forever != rows[j].Forever {
			return !rows[i].Forever
		}
		return rows[i].Until.After(rows[j].Until)
	})
	if len(rows) > 200 {
		rows = rows[:200]
	}
	e.bans, e.banCount, e.netCount = rows, count, nets
}

func (e *Engine) scanBusiest() {
	m := e.gate.Map("ip_stats")
	var k kern.AddrKey
	var v kern.IPState
	kNow := kern.Now()
	var top []Talker
	it := m.Iterate()
	for n := 0; n < 50000 && it.Next(&k, &v); n++ {
		if kNow-v.WinStart > 2e9 || v.Pkts == 0 {
			continue
		}
		top = append(top, Talker{kern.AddrOf(k.A).String(), v.Pkts, v.Bytes, v.Score})
	}
	sort.Slice(top, func(i, j int) bool { return top[i].Pkts > top[j].Pkts })
	if len(top) > 10 {
		top = top[:10]
	}
	e.busiest = top
}

func (e *Engine) writeStatus(now time.Time, s Sample, totals [kern.CMax]kern.Ctr) {
	st := Status{
		Version: Version, Pid: os.Getpid(), Iface: e.gate.Iface, Mode: e.gate.Mode,
		Profile: e.cfg.Profile, Level: e.cfg.Level, Observe: e.cfg.Observe,
		Kernel: kern.KernelRelease(), Pipeline: e.gate.Level, Tracking: e.gate.Tracking,
		Features: e.gate.Features, Started: e.started, Updated: now,
		Now: s, PeakPPS: e.peakPPS, PeakBPS: e.peakBPS,
		Normal: e.det.Mean, Trigger: e.det.Trigger(), Learning: e.det.Learning(),
		Totals: totals, History: e.history,
		BanCount: e.banCount, NetworkCount: e.netCount, AllowCount: e.allowN,
		Bans: e.bans, Events: e.events, Attacks: e.attacks, Busiest: e.busiest,
		Limits: e.cfg.Limits, Problems: e.problems,
	}
	if e.det.Active {
		st.Attack = &AttackRow{Start: e.det.Since, Kind: e.det.Kind, PeakPPS: e.det.PeakPPS,
			PeakBPS: e.det.PeakBPS, Dropped: e.det.Dropped, Bans: e.attackBan}
	}
	raw, err := json.Marshal(&st)
	if err != nil {
		return
	}
	_ = config.WriteFile(StatusFile, raw, 0o644)
}

func leftText(d time.Duration, forever bool) string {
	if forever {
		return "until removed"
	}
	return "for " + d.Round(time.Minute).String()
}

func statePath() string { return filepath.Join(config.StateDir, "state.json") }

// save keeps bans and the learned normal level across restarts.
func (e *Engine) save() {
	if e.gate == nil {
		return
	}
	st := savedState{SavedAt: time.Now(), Detector: e.det, Attacks: e.attacks}
	kNow := kern.Now()
	unix := func(until uint64) int64 {
		if until == 0 {
			return 0
		}
		return st.SavedAt.Add(time.Duration(int64(until) - int64(kNow))).Unix()
	}
	var k kern.AddrKey
	var v kern.BanVal
	it := e.gate.Map("bans").Iterate()
	for it.Next(&k, &v) {
		if v.Until != 0 && v.Until <= kNow {
			continue
		}
		st.Bans = append(st.Bans, savedBan{kern.AddrOf(k.A).String(), unix(v.Until), v.Reason, v.Strikes})
	}
	var lk kern.LpmKey
	it = e.gate.Map("subnets").Iterate()
	for it.Next(&lk, &v) {
		// Permanent entries come from block.list; only timed ones are saved.
		if v.Until == 0 || v.Until <= kNow {
			continue
		}
		st.Networks = append(st.Networks, savedBan{kern.PrefixOf(lk).String(), unix(v.Until), v.Reason, v.Strikes})
	}
	raw, err := json.Marshal(&st)
	if err != nil {
		return
	}
	if err := config.WriteFile(statePath(), raw, 0o600); err != nil {
		e.logf("could not save state: %v", err)
	}
}

func (e *Engine) restore() {
	raw, err := os.ReadFile(statePath())
	if err != nil {
		return
	}
	var st savedState
	st.Detector = e.det
	if json.Unmarshal(raw, &st) != nil {
		return
	}
	e.attacks = st.Attacks
	now, kNow := time.Now(), kern.Now()
	until := func(unix int64) (uint64, bool) {
		if unix == 0 {
			return 0, true
		}
		left := time.Unix(unix, 0).Sub(now)
		if left <= 0 {
			return 0, false
		}
		return kNow + uint64(left), true
	}
	n := 0
	for _, b := range st.Bans {
		addr, err := netip.ParseAddr(b.Target)
		u, ok := until(b.Until)
		if err != nil || !ok {
			continue
		}
		key := kern.KeyOf(addr)
		if e.gate.Map("bans").Put(key, kern.BanVal{Until: u, Reason: b.Reason, Strikes: b.Strikes}) == nil {
			e.known[key] = true
			n++
		}
	}
	for _, b := range st.Networks {
		p, err := netip.ParsePrefix(b.Target)
		u, ok := until(b.Until)
		if err != nil || !ok {
			continue
		}
		if e.gate.Map("subnets").Put(kern.LpmOf(p), kern.BanVal{Until: u, Reason: b.Reason}) == nil {
			e.hasSubnet = true
			n++
		}
	}
	if n > 0 {
		e.logf("restored %d bans from before the restart", n)
	}
}

func human(v float64) string {
	switch {
	case v >= 1e9:
		return fmt.Sprintf("%.1fG", v/1e9)
	case v >= 1e6:
		return fmt.Sprintf("%.1fM", v/1e6)
	case v >= 1e4:
		return fmt.Sprintf("%.0fK", v/1e3)
	case v >= 1e3:
		return fmt.Sprintf("%.1fK", v/1e3)
	}
	return fmt.Sprintf("%.0f", v)
}

// Human formats a count the way the live screen does.
func Human(v float64) string { return human(v) }
