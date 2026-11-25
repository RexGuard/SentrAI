package config

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RexGuard/SentrAI/gate/internal/kern"
)

func TestEveryProfileAndLevelIsValid(t *testing.T) {
	for _, p := range Profiles {
		var last uint32
		for _, l := range Levels {
			c, err := FromProfile(p.Name, l.Name)
			if err != nil {
				t.Fatalf("%s/%s: %v", p.Name, l.Name, err)
			}
			if err := c.Validate(); err != nil {
				t.Errorf("%s/%s: %v", p.Name, l.Name, err)
			}
			if c.Limits.Packets <= last {
				t.Errorf("%s/%s: a busier level must have looser limits (%d after %d)", p.Name, l.Name, c.Limits.Packets, last)
			}
			last = c.Limits.Packets
			if c.Attack.MinPackets <= c.Limits.Packets {
				t.Errorf("%s/%s: the attack line must sit above one sender's limit", p.Name, l.Name)
			}
		}
	}
	if _, err := FromProfile("nope", "normal"); err == nil {
		t.Error("unknown profile should be refused")
	}
	if _, err := FromProfile("game", "nope"); err == nil {
		t.Error("unknown level should be refused")
	}
}

func TestRenderedFileLoadsBackTheSame(t *testing.T) {
	text, err := Render("eth0", "game", "busy", true)
	if err != nil {
		t.Fatal(err)
	}
	c, err := Parse([]byte(text))
	if err != nil {
		t.Fatalf("rendered file does not load: %v\n%s", err, text)
	}
	want, _ := FromProfile("game", "busy")
	if c.Interface != "eth0" || !c.Observe || c.Limits != want.Limits || c.Scoring != want.Scoring {
		t.Errorf("loaded settings differ from the profile: %+v", c)
	}
	// Uncommenting the example block must still give a valid file.
	head, examples, _ := strings.Cut(text, "profile's values:\n#\n")
	open := head + strings.ReplaceAll("\n"+examples, "\n# ", "\n")
	if _, err := Parse([]byte(open)); err != nil {
		t.Errorf("file with the examples switched on does not load: %v", err)
	}
}

func TestOverridesWinOverProfile(t *testing.T) {
	c, err := Parse([]byte("interface: eth0\nprofile: website\nlimits:\n  packets: 4242\nbans:\n  seconds: 60\n"))
	if err != nil {
		t.Fatal(err)
	}
	base, _ := FromProfile("website", "normal")
	if c.Limits.Packets != 4242 || c.Bans.Seconds != 60 {
		t.Errorf("override ignored: %+v", c.Limits)
	}
	if c.Limits.UDP != base.Limits.UDP {
		t.Error("values not in the file should come from the profile")
	}
}

func TestBadSettingsAreRefused(t *testing.T) {
	for _, bad := range []string{
		"mode: warp",
		"checks:\n  fragments: maybe",
		"bans:\n  seconds: 0",
		"attack:\n  tighten_percent: 150",
		"limits: [",
	} {
		if _, err := Parse([]byte("interface: eth0\n" + bad + "\n")); err == nil {
			t.Errorf("%q should be refused", bad)
		}
	}
}

func TestKernelSettings(t *testing.T) {
	c, _ := FromProfile("balanced", "normal")
	k := c.Kernel(true, false, true, true)
	for _, f := range []uint32{kern.FEnabled, kern.FRate, kern.FDropBogon, kern.FDropBadTCP, kern.FAmp, kern.FReflect, kern.FHasAllow, kern.FTrack, kern.FAttack, kern.FDropFragsAttack} {
		if k.Flags&f == 0 {
			t.Errorf("switch %#x should be on", f)
		}
	}
	for _, f := range []uint32{kern.FObserve, kern.FDropPrivate, kern.FHasSubnets, kern.FToken, kern.FDropFrags} {
		if k.Flags&f != 0 {
			t.Errorf("switch %#x should be off", f)
		}
	}
	if k.StrikeMult != [8]uint32{1, 2, 4, 8, 24, 72, 72, 72} {
		t.Errorf("repeat steps = %v", k.StrikeMult)
	}
	if k.AmpPort[0] != 53 || k.Pps != c.Limits.Packets || k.TokenRate != 0 {
		t.Errorf("kernel settings = %+v", k)
	}
}

func TestLists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allow.list")
	if e, _, err := ReadList(path); err != nil || len(e) != 0 {
		t.Fatalf("missing file should be an empty list: %v %v", e, err)
	}
	add := func(s, note string) bool {
		p, err := kern.ParseTarget(s)
		if err != nil {
			t.Fatal(err)
		}
		changed, err := AddToList(path, AllowHeading, Entry{p, note})
		if err != nil {
			t.Fatal(err)
		}
		return changed
	}
	if !add("1.2.3.4", "office") || !add("10.0.0.0/8", "") || !add("2001:db8::/32", "v6") {
		t.Fatal("first adds should change the list")
	}
	if add("1.2.3.4", "office") {
		t.Error("adding the same entry twice should change nothing")
	}
	raw, _ := os.ReadFile(path)
	if err := os.WriteFile(path, append(raw, []byte("not-an-address\n1.2.3.4 # twice\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	entries, problems, err := ReadList(path)
	if err != nil || len(entries) != 3 || len(problems) != 1 {
		t.Fatalf("entries=%v problems=%v err=%v", entries, problems, err)
	}
	if entries[0].Note != "office" || entries[0].String() != "1.2.3.4  # office" {
		t.Errorf("entry = %q", entries[0])
	}
	if ok, _ := RemoveFromList(path, AllowHeading, netip.MustParsePrefix("10.0.0.0/8")); !ok {
		t.Error("remove should find the entry")
	}
	if ok, _ := RemoveFromList(path, AllowHeading, netip.MustParsePrefix("10.0.0.0/8")); ok {
		t.Error("second remove should find nothing")
	}
}

func TestSuggest(t *testing.T) {
	cases := map[string][]string{
		"game":     {"tcp/22", "udp/25565"},
		"hosting":  {"tcp/22", "tcp/2022", "tcp/443"},
		"database": {"tcp/22", "tcp/5432"},
		"balanced": {"tcp/443", "tcp/3306"},
		"website":  {"tcp/80", "tcp/443", "tcp/22"},
	}
	for want, ports := range cases {
		if got, _ := Suggest(PortNames(ports)); got != want {
			t.Errorf("%v: suggested %s, want %s", ports, got, want)
		}
	}
	if got, _ := Suggest(nil); got != "balanced" {
		t.Errorf("nothing listening: %s", got)
	}
}
