// sentrai-gate: a standalone firewall for one Linux machine. No account,
// no sign-in, no panel. It drops attack traffic at the network card and
// never sends anything back at the sender.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/RexGuard/SentrAI/gate/internal/config"
	"github.com/RexGuard/SentrAI/gate/internal/engine"
	"github.com/RexGuard/SentrAI/gate/internal/kern"
	"github.com/RexGuard/SentrAI/gate/internal/tui"
)

const usage = `SentrAI Gate: guards one Linux machine at the network card.

  sentrai-gate status              One-screen summary
  sentrai-gate stats               Live screen (also: top)
  sentrai-gate doctor              Check this machine can run the gate

  sentrai-gate allow add 1.2.3.4 [note]     Never drop, limit or ban this sender
  sentrai-gate allow remove 1.2.3.4
  sentrai-gate allow list
  sentrai-gate block add 5.6.7.0/24 [note]  Always drop this sender
  sentrai-gate block remove 5.6.7.0/24
  sentrai-gate block list
  sentrai-gate ban 1.2.3.4 [2h] [note]      Drop for a while (default 1h)
  sentrai-gate unban 1.2.3.4
  sentrai-gate bans                         Who is banned right now (sudo)

  sentrai-gate profile list        Ready-made settings and traffic levels
  sentrai-gate profile set game busy
  sentrai-gate profile suggest     Pick one from what this machine runs
  sentrai-gate observe on|off      Watch only: count, drop nothing
  sentrai-gate reload              Apply edited settings and lists
  sentrai-gate events [n]          Recent bans and attacks (sudo)
  sentrai-gate attacks             Past attacks

  sentrai-gate start|stop|restart  Control the background service
  sentrai-gate run                 Run in this terminal (Ctrl+C stops it)
  sentrai-gate version

Addresses can be IPv4 or IPv6, single or a network like 10.0.0.0/8.
Settings: /etc/sentrai-gate/config.yaml`

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Println(usage)
		return
	}
	var err error
	switch args[0] {
	case "help", "-h", "--help":
		fmt.Println(usage)
	case "version", "-v", "--version":
		fmt.Println("sentrai-gate", engine.Version)
	case "run":
		err = cmdRun(args[1:])
	case "status", "st":
		err = cmdStatus(args[1:])
	case "stats", "top", "tui":
		err = tui.Run()
	case "doctor":
		err = cmdDoctor()
	case "allow":
		err = cmdList(args[1:], config.AllowFile, config.AllowHeading, "allow")
	case "block":
		err = cmdList(args[1:], config.BlockFile, config.BlockHeading, "block")
	case "ban":
		err = cmdBan(args[1:])
	case "unban":
		err = cmdUnban(args[1:])
	case "bans":
		err = cmdBans()
	case "profile":
		err = cmdProfile(args[1:])
	case "observe":
		err = cmdObserve(args[1:])
	case "reload":
		err = cmdReload(true)
	case "events":
		err = cmdEvents(args[1:])
	case "attacks":
		err = cmdAttacks()
	case "start", "stop", "restart":
		err = systemctl(args[0])
	case "config":
		err = cmdConfig(args[1:])
	case "whoami":
		// Used by the installer: the address you are connected from.
		if a := sshClient(); a.IsValid() {
			fmt.Println(a)
		}
	default:
		err = fmt.Errorf("unknown command %q. Run: sentrai-gate help", args[0])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "sentrai-gate:", err)
		os.Exit(1)
	}
}

func needRoot() error {
	if os.Geteuid() != 0 {
		return errors.New("this needs root. Run it again with sudo")
	}
	return nil
}

func cmdRun(args []string) error {
	if err := needRoot(); err != nil {
		return err
	}
	path := config.File
	for i := 0; i < len(args); i++ {
		if args[i] == "--config" && i+1 < len(args) {
			path = args[i+1]
			i++
		}
	}
	if kern.Running() {
		if pid := runningPid(); pid > 0 {
			return fmt.Errorf("the gate is already running (process %d). Stop it first: sudo sentrai-gate stop", pid)
		}
	}
	e := &engine.Engine{ConfigPath: path, Log: func(format string, a ...any) {
		fmt.Printf(format+"\n", a...)
	}}
	return e.Run(context.Background())
}

func runningPid() int {
	raw, err := os.ReadFile(engine.PidFile)
	if err != nil {
		return 0
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(raw)))
	if pid <= 0 || syscall.Kill(pid, 0) != nil {
		return 0
	}
	return pid
}

func cmdReload(loud bool) error {
	pid := runningPid()
	if pid == 0 {
		if loud {
			return errors.New("the gate is not running, so there is nothing to reload. Start it with: sudo sentrai-gate start")
		}
		return nil
	}
	if _, err := config.Load(config.File); err != nil {
		return err
	}
	if err := syscall.Kill(pid, syscall.SIGHUP); err != nil {
		return fmt.Errorf("could not signal the gate: %w (try with sudo)", err)
	}
	if loud {
		fmt.Println("Reloaded settings and lists.")
	}
	return nil
}

func systemctl(verb string) error {
	if err := needRoot(); err != nil {
		return err
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return errors.New("this machine has no systemd. Run the gate yourself with: sudo sentrai-gate run")
	}
	cmd := exec.Command("systemctl", verb, "sentrai-gate")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("systemctl %s failed. See why: journalctl -u sentrai-gate -n 30", verb)
	}
	switch verb {
	case "stop":
		fmt.Println("Stopped. Traffic is no longer filtered.")
	default:
		fmt.Println("Running. See it live: sentrai-gate stats")
	}
	return nil
}

func cmdStatus(args []string) error {
	st, stale, err := engine.ReadStatus()
	if err != nil || stale {
		if len(args) > 0 && args[0] == "--json" {
			fmt.Println(`{"running":false}`)
			return nil
		}
		fmt.Println("SentrAI Gate is not running. Traffic is not being filtered.")
		fmt.Println("Start it with: sudo sentrai-gate start")
		return nil
	}
	if len(args) > 0 && args[0] == "--json" {
		raw, _ := json.MarshalIndent(st, "", "  ")
		fmt.Println(string(raw))
		return nil
	}
	lines := tui.Render(st, stale, 0, 100, 34)
	tui.Print(lines[:len(lines)-1])
	fmt.Println("Live screen: sentrai-gate stats")
	return nil
}

func cmdList(args []string, file, heading, kind string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch args[0] {
	case "list", "ls":
		entries, problems, err := config.ReadList(file)
		if err != nil {
			return err
		}
		if len(entries) == 0 {
			fmt.Printf("The %s list is empty.\n", kind)
		}
		for _, e := range entries {
			fmt.Println(e)
		}
		for _, p := range problems {
			fmt.Fprintln(os.Stderr, "!", p)
		}
		return nil
	case "add":
		if len(args) < 2 {
			return fmt.Errorf("say who: sentrai-gate %s add 1.2.3.4 [note]", kind)
		}
		if err := needRoot(); err != nil {
			return err
		}
		p, err := kern.ParseTarget(args[1])
		if err != nil {
			return err
		}
		if kind == "block" {
			if err := refuseDangerous(p); err != nil {
				return err
			}
		}
		changed, err := config.AddToList(file, heading, config.Entry{Net: p, Note: strings.Join(args[2:], " ")})
		if err != nil {
			return err
		}
		if kind == "allow" {
			// An allowed sender should not stay banned.
			liveUnban(p)
		}
		if !changed {
			fmt.Printf("%s is already on the %s list.\n", show(p), kind)
		} else if kind == "allow" {
			fmt.Printf("%s will never be dropped, limited or banned.\n", show(p))
		} else {
			fmt.Printf("%s will always be dropped.\n", show(p))
		}
		return cmdReload(false)
	case "remove", "rm", "del":
		if len(args) < 2 {
			return fmt.Errorf("say who: sentrai-gate %s remove 1.2.3.4", kind)
		}
		if err := needRoot(); err != nil {
			return err
		}
		p, err := kern.ParseTarget(args[1])
		if err != nil {
			return err
		}
		found, err := config.RemoveFromList(file, heading, p)
		if err != nil {
			return err
		}
		if !found {
			fmt.Printf("%s was not on the %s list.\n", show(p), kind)
			return nil
		}
		fmt.Printf("Removed %s from the %s list.\n", show(p), kind)
		return cmdReload(false)
	}
	return fmt.Errorf("use: sentrai-gate %s add|remove|list", kind)
}

func show(p netip.Prefix) string {
	if p.IsSingleIP() {
		return p.Addr().String()
	}
	return p.String()
}

// refuseDangerous stops a block that would cut the machine off from
// everyone, or from the person typing the command.
func refuseDangerous(p netip.Prefix) error {
	if (p.Addr().Is4() && p.Bits() < 8) || (p.Addr().Is6() && p.Bits() < 16) {
		return fmt.Errorf("%s is too much of the internet to block in one go", p)
	}
	if me := sshClient(); me.IsValid() && p.Contains(me) {
		return fmt.Errorf("%s includes %s, the address you are connected from. That would lock you out", show(p), me)
	}
	return nil
}

// sshClient finds the address of the person typing, when they came in over
// SSH. sudo hides the SSH details, so it also looks at the processes above
// this one.
func sshClient() netip.Addr {
	parse := func(v string) netip.Addr {
		if f := strings.Fields(v); len(f) > 0 {
			if a, err := netip.ParseAddr(f[0]); err == nil {
				return a.Unmap()
			}
		}
		return netip.Addr{}
	}
	for _, env := range []string{"SSH_CONNECTION", "SSH_CLIENT"} {
		if a := parse(os.Getenv(env)); a.IsValid() {
			return a
		}
	}
	pid := os.Getppid()
	for hops := 0; pid > 1 && hops < 12; hops++ {
		if raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid)); err == nil {
			for _, kv := range strings.Split(string(raw), "\x00") {
				if v, ok := strings.CutPrefix(kv, "SSH_CONNECTION="); ok {
					if a := parse(v); a.IsValid() {
						return a
					}
				}
			}
		}
		stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			break
		}
		// "pid (name) state ppid ...": the name may hold spaces.
		rest := string(stat)
		if i := strings.LastIndexByte(rest, ')'); i >= 0 {
			rest = rest[i+1:]
		}
		f := strings.Fields(rest)
		if len(f) < 2 {
			break
		}
		pid, _ = strconv.Atoi(f[1])
	}
	return netip.Addr{}
}

func parseLength(s string) (time.Duration, bool) {
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return d, true
	}
	if strings.HasSuffix(s, "d") {
		if n, err := strconv.Atoi(strings.TrimSuffix(s, "d")); err == nil && n > 0 {
			return time.Duration(n) * 24 * time.Hour, true
		}
	}
	return 0, false
}

func cmdBan(args []string) error {
	if len(args) == 0 {
		return errors.New("say who: sentrai-gate ban 1.2.3.4 [2h]")
	}
	if err := needRoot(); err != nil {
		return err
	}
	p, err := kern.ParseTarget(args[0])
	if err != nil {
		return err
	}
	if err := refuseDangerous(p); err != nil {
		return err
	}
	length := time.Hour
	if len(args) > 1 {
		if d, ok := parseLength(args[1]); ok {
			length = d
		}
	}
	if length > 30*24*time.Hour {
		return errors.New("a timed ban lasts 30 days at most. For longer use: sentrai-gate block add")
	}
	val := kern.BanVal{Until: kern.Now() + uint64(length), Reason: kern.RManual}
	if p.IsSingleIP() {
		m, err := kern.OpenPinned("bans")
		if err != nil {
			return err
		}
		defer m.Close()
		if err := m.Put(kern.KeyOf(p.Addr()), val); err != nil {
			return err
		}
	} else {
		m, err := kern.OpenPinned("subnets")
		if err != nil {
			return err
		}
		defer m.Close()
		if err := m.Put(kern.LpmOf(p), val); err != nil {
			return err
		}
	}
	fmt.Printf("Banned %s for %s.\n", show(p), length)
	return nil
}

func liveUnban(p netip.Prefix) bool {
	removed := false
	if p.IsSingleIP() {
		if m, err := kern.OpenPinned("bans"); err == nil {
			removed = m.Delete(kern.KeyOf(p.Addr())) == nil
			m.Close()
		}
	}
	if m, err := kern.OpenPinned("subnets"); err == nil {
		var v kern.BanVal
		k := kern.LpmOf(p)
		// Only an exact entry, and never one that comes from block.list.
		if m.Lookup(k, &v) == nil && !(v.Until == 0 && v.Reason&kern.RManual != 0) {
			removed = m.Delete(k) == nil || removed
		}
		m.Close()
	}
	return removed
}

func cmdUnban(args []string) error {
	if len(args) == 0 {
		return errors.New("say who: sentrai-gate unban 1.2.3.4")
	}
	if err := needRoot(); err != nil {
		return err
	}
	p, err := kern.ParseTarget(args[0])
	if err != nil {
		return err
	}
	if !kern.Running() {
		return errors.New("the gate is not running")
	}
	if liveUnban(p) {
		fmt.Printf("Unbanned %s.\n", show(p))
		return nil
	}
	if entries, _, _ := config.ReadList(config.BlockFile); len(entries) > 0 {
		for _, e := range entries {
			if e.Net == p {
				return fmt.Errorf("%s is on the block list. Remove it with: sudo sentrai-gate block remove %s", show(p), show(p))
			}
			if e.Net.Contains(p.Addr()) {
				return fmt.Errorf("%s is inside %s on the block list", show(p), e.Net)
			}
		}
	}
	fmt.Printf("%s was not banned.\n", show(p))
	return nil
}

func cmdBans() error {
	bm, err := kern.OpenPinned("bans")
	if err != nil {
		return err
	}
	defer bm.Close()
	sm, err := kern.OpenPinned("subnets")
	if err != nil {
		return err
	}
	defer sm.Close()

	now := kern.Now()
	type row struct {
		target, left, why string
		until             uint64
	}
	var rows []row
	leftOf := func(until uint64) string {
		if until == 0 {
			return "until removed"
		}
		return (time.Duration(until - now)).Round(time.Second).String() + " left"
	}
	var k kern.AddrKey
	var v kern.BanVal
	it := bm.Iterate()
	for it.Next(&k, &v) {
		if v.Until != 0 && v.Until <= now {
			continue
		}
		why := kern.ReasonText(v.Reason)
		if v.Strikes > 1 {
			why += fmt.Sprintf(" (strike %d)", v.Strikes)
		}
		rows = append(rows, row{kern.AddrOf(k.A).String(), leftOf(v.Until), why, v.Until})
	}
	var lk kern.LpmKey
	it = sm.Iterate()
	for it.Next(&lk, &v) {
		if v.Until != 0 && v.Until <= now {
			continue
		}
		why := kern.ReasonText(v.Reason)
		if v.Until == 0 && v.Reason&kern.RManual != 0 {
			why = "on the block list"
		}
		rows = append(rows, row{show(kern.PrefixOf(lk)), leftOf(v.Until), why, v.Until})
	}
	if len(rows) == 0 {
		fmt.Println("Nobody is banned.")
		return nil
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].target < rows[j].target })
	for _, r := range rows {
		fmt.Printf("%-40s %-18s %s\n", r.target, r.left, r.why)
	}
	fmt.Printf("\n%d in total.\n", len(rows))
	return nil
}

func cmdProfile(args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch args[0] {
	case "list", "ls":
		current, level := "", ""
		if c, err := config.Load(config.File); err == nil {
			current, level = c.Profile, c.Level
		}
		fmt.Println("Profiles (what the machine is for):")
		for _, p := range config.Profiles {
			c, _ := config.FromProfile(p.Name, "normal")
			mark := "  "
			if p.Name == current {
				mark = "> "
			}
			fmt.Printf("%s%-12s %s\n%14s per sender each second: %d packets, %d new connections\n", mark, p.Name, p.For, "",
				c.Limits.Packets, c.Limits.NewConnections)
		}
		fmt.Println("\nLevels (how busy it is). Each one scales the profile's limits:")
		for _, l := range config.Levels {
			mark := "  "
			if l.Name == level {
				mark = "> "
			}
			fmt.Printf("%s%-12s x%-5.2g %s\n", mark, l.Name, l.Times, l.For)
		}
		fmt.Println("\nChange with: sudo sentrai-gate profile set <profile> [level]")
		return nil
	case "suggest":
		ports := listening()
		name, why := config.Suggest(config.PortNames(ports))
		fmt.Printf("Suggested profile: %s (%s).\n", name, why)
		fmt.Printf("Use it with: sudo sentrai-gate profile set %s\n", name)
		return nil
	case "set":
		if len(args) < 2 {
			return errors.New("say which: sentrai-gate profile set game [busy]")
		}
		if err := needRoot(); err != nil {
			return err
		}
		level := ""
		if len(args) > 2 {
			level = args[2]
		}
		cur, err := config.Load(config.File)
		if err != nil {
			return err
		}
		if level == "" {
			level = cur.Level
		}
		if _, err := config.FromProfile(args[1], level); err != nil {
			return err
		}
		if err := setKeys(map[string]string{"profile": args[1], "level": level}); err != nil {
			return err
		}
		fmt.Printf("Profile is now %s / %s. Values you set yourself in the settings file still win.\n", args[1], level)
		return cmdReload(false)
	}
	return errors.New("use: sentrai-gate profile list|set|suggest")
}

// setKeys changes top-level "key: value" lines in the settings file and
// leaves everything else, comments included, as it was.
func setKeys(kv map[string]string) error {
	raw, err := os.ReadFile(config.File)
	if err != nil {
		return err
	}
	text := string(raw)
	for k, v := range kv {
		re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(k) + `:.*$`)
		if re.MatchString(text) {
			text = re.ReplaceAllString(text, k+": "+v)
		} else {
			text = strings.TrimRight(text, "\n") + "\n" + k + ": " + v + "\n"
		}
	}
	if _, err := config.Parse([]byte(text)); err != nil {
		return err
	}
	return config.WriteFile(config.File, []byte(text), 0o644)
}

func cmdObserve(args []string) error {
	if len(args) != 1 || (args[0] != "on" && args[0] != "off") {
		return errors.New("use: sentrai-gate observe on|off")
	}
	if err := needRoot(); err != nil {
		return err
	}
	on := args[0] == "on"
	if err := setKeys(map[string]string{"observe": strconv.FormatBool(on)}); err != nil {
		return err
	}
	if on {
		fmt.Println("Watching only. The gate counts what it would drop and drops nothing.")
	} else {
		fmt.Println("Guarding. The gate now drops what it catches.")
	}
	return cmdReload(false)
}

func cmdEvents(args []string) error {
	n := 30
	if len(args) > 0 {
		if v, err := strconv.Atoi(args[0]); err == nil && v > 0 {
			n = v
		}
	}
	f, err := os.Open(filepath.Join(config.LogDir, "events.log"))
	if errors.Is(err, os.ErrPermission) {
		return needRoot()
	}
	if err != nil {
		fmt.Println("Nothing has happened yet.")
		return nil
	}
	defer f.Close()
	var rows []engine.EventRow
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<16), 1<<20)
	for sc.Scan() {
		var r engine.EventRow
		if json.Unmarshal(sc.Bytes(), &r) == nil {
			rows = append(rows, r)
			if len(rows) > n {
				rows = rows[1:]
			}
		}
	}
	for _, r := range rows {
		fmt.Printf("%s  %s\n", r.Time.Local().Format("2 Jan 15:04:05"), r.Text)
	}
	return nil
}

func cmdAttacks() error {
	st, stale, err := engine.ReadStatus()
	if err != nil || stale {
		return errors.New("the gate is not running")
	}
	lines := tui.Render(st, false, 3, 120, 30)
	tui.Print(lines[2 : len(lines)-1])
	return nil
}

func cmdConfig(args []string) error {
	if len(args) == 0 || args[0] != "init" {
		return errors.New("use: sentrai-gate config init [--interface eth0] [--profile balanced] [--level normal] [--observe] [--force]")
	}
	if err := needRoot(); err != nil {
		return err
	}
	iface, profile, level, observe, force := "", "", "normal", false, false
	for i := 1; i < len(args); i++ {
		next := func() string {
			if i+1 < len(args) {
				i++
				return args[i]
			}
			return ""
		}
		switch args[i] {
		case "--interface":
			iface = next()
		case "--profile":
			profile = next()
		case "--level":
			level = next()
		case "--observe":
			observe = true
		case "--force":
			force = true
		}
	}
	if _, err := os.Stat(config.File); err == nil && !force {
		fmt.Println("Settings already exist at", config.File, "and were left alone.")
		return nil
	}
	if iface == "" {
		iface = defaultInterface()
	}
	if iface == "" {
		return errors.New("could not tell which network card faces the internet. Say so with --interface")
	}
	if _, err := net.InterfaceByName(iface); err != nil {
		return fmt.Errorf("there is no network card called %q", iface)
	}
	if profile == "" {
		var why string
		profile, why = config.Suggest(config.PortNames(listening()))
		fmt.Printf("Profile: %s (%s).\n", profile, why)
	}
	text, err := config.Render(iface, profile, level, observe)
	if err != nil {
		return err
	}
	if err := config.WriteFile(config.File, []byte(text), 0o644); err != nil {
		return err
	}
	for _, l := range []struct{ file, heading string }{{config.AllowFile, config.AllowHeading}, {config.BlockFile, config.BlockHeading}} {
		if _, err := os.Stat(l.file); os.IsNotExist(err) {
			_ = config.WriteList(l.file, l.heading, nil)
		}
	}
	fmt.Printf("Wrote %s for %s.\n", config.File, iface)
	return nil
}

// defaultInterface finds the network card the default route uses.
func defaultInterface() string {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := strings.Fields(sc.Text())
		if len(p) > 2 && p[1] == "00000000" {
			return p[0]
		}
	}
	// IPv6-only machine.
	if f6, err := os.Open("/proc/net/ipv6_route"); err == nil {
		defer f6.Close()
		sc := bufio.NewScanner(f6)
		for sc.Scan() {
			p := strings.Fields(sc.Text())
			if len(p) == 10 && p[0] == strings.Repeat("0", 32) && p[1] == "00" && p[9] != "lo" {
				return p[9]
			}
		}
	}
	return ""
}

// listening returns "tcp/443"-style names for the services on this machine.
func listening() []string {
	seen := map[string]bool{}
	read := func(path, proto string, onlyListen bool) {
		f, err := os.Open(path)
		if err != nil {
			return
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Scan()
		for sc.Scan() {
			p := strings.Fields(sc.Text())
			if len(p) < 4 || (onlyListen && p[3] != "0A") {
				continue
			}
			i := strings.LastIndexByte(p[1], ':')
			if i < 0 {
				continue
			}
			if port, err := strconv.ParseUint(p[1][i+1:], 16, 16); err == nil && port > 0 {
				seen[fmt.Sprintf("%s/%d", proto, port)] = true
			}
		}
	}
	read("/proc/net/tcp", "tcp", true)
	read("/proc/net/tcp6", "tcp", true)
	read("/proc/net/udp", "udp", false)
	read("/proc/net/udp6", "udp", false)
	return config.SortedKeys(seen)
}

func cmdDoctor() error {
	ok := true
	line := func(good bool, text, fix string) {
		mark := "ok  "
		if !good {
			mark = "FAIL"
			ok = false
		}
		fmt.Printf("[%s] %s\n", mark, text)
		if !good && fix != "" {
			fmt.Printf("       %s\n", fix)
		}
	}
	note := func(text, detail string) {
		fmt.Printf("[note] %s\n", text)
		if detail != "" {
			fmt.Printf("       %s\n", detail)
		}
	}

	root := os.Geteuid() == 0
	line(root, "Running as root", "Run: sudo sentrai-gate doctor")
	major, minor := kern.KernelVersion()
	line(major > 5 || (major == 5 && minor >= 10), fmt.Sprintf("Kernel %s", kern.KernelRelease()),
		"SentrAI Gate needs Linux 5.10 or newer.")

	if kern.BPFFSMounted() {
		line(true, "BPF file system at /sys/fs/bpf", "")
	} else {
		note("BPF file system is not mounted at /sys/fs/bpf", "The gate mounts it by itself when it starts.")
	}

	if root {
		for i, f := range kern.Probe() {
			if i < 3 {
				line(f.On, f.Name, f.Note)
			} else if f.On {
				line(true, f.Name, "")
			} else {
				note(f.Name+": not on this kernel", "The gate still works. "+f.Note+".")
			}
		}
		g, err := kern.Load(kern.Options{MaxLevel: 2, MaxAddresses: 1024, MaxBans: 1024})
		if err != nil {
			line(false, "The kernel accepts the packet filter", err.Error())
		} else {
			switch g.Level {
			case 2:
				line(true, "The kernel accepts the full packet filter", "")
			default:
				for _, f := range g.Features {
					if f.Name == "Full pipeline" {
						note("The kernel accepts a simpler packet filter", f.Note)
					}
				}
			}
			g.Close()
		}
	}

	cfg, err := config.Load(config.File)
	if err != nil {
		line(false, "Settings file "+config.File, err.Error())
	} else {
		line(true, fmt.Sprintf("Settings file: profile %s / %s", cfg.Profile, cfg.Level), "")
		_, ierr := net.InterfaceByName(cfg.Interface)
		driver := ""
		if l, err := os.Readlink("/sys/class/net/" + cfg.Interface + "/device/driver"); err == nil {
			driver = " (driver " + filepath.Base(l) + ")"
		}
		line(ierr == nil, "Network card "+cfg.Interface+driver, "Set the right one as interface: in "+config.File)
		if cfg.Observe {
			note("Observe mode is on", "The gate counts what it would drop and drops nothing. Turn off with: sudo sentrai-gate observe off")
		}
	}
	for _, file := range []string{config.AllowFile, config.BlockFile} {
		_, problems, _ := config.ReadList(file)
		line(len(problems) == 0, "List file "+file, strings.Join(problems, "; "))
	}
	if me := sshClient(); me.IsValid() {
		entries, _, _ := config.ReadList(config.AllowFile)
		found := false
		for _, e := range entries {
			found = found || e.Net.Contains(me)
		}
		if found {
			line(true, fmt.Sprintf("Your address %s is on the allow list", me), "")
		} else {
			note(fmt.Sprintf("Your address %s is not on the allow list", me),
				"Add it so you can never be locked out: sudo sentrai-gate allow add "+me.String()+" me")
		}
	}
	if st, stale, err := engine.ReadStatus(); err == nil && !stale {
		line(true, fmt.Sprintf("The gate is running on %s in %s mode", st.Iface, st.Mode), "")
	} else {
		note("The gate is not running", "Start it with: sudo sentrai-gate start")
	}

	if !ok {
		return errors.New("some checks failed")
	}
	fmt.Println("\nThis machine can run SentrAI Gate.")
	return nil
}
