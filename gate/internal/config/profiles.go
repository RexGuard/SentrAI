package config

import (
	"fmt"
	"sort"
	"strings"
)

// Profile is a ready-made set of limits for one kind of machine.
type Profile struct {
	Name string
	For  string // one line: what kind of machine

	packets, newConns, udp, icmp uint32
	mbytes                       uint64 // megabytes per second per address
	banSeconds                   uint32
	unaskedReplies               bool
	autoNetwork                  bool
}

// Profiles, from strictest to loosest.
var Profiles = []Profile{
	{Name: "locked-down", For: "Admin panels, login pages, a private site only a few people use",
		packets: 300, newConns: 40, udp: 100, icmp: 20, mbytes: 4, banSeconds: 7200, unaskedReplies: true, autoNetwork: true},
	{Name: "website", For: "Blogs, shops and company sites",
		packets: 700, newConns: 120, udp: 250, icmp: 40, mbytes: 8, banSeconds: 3600, unaskedReplies: true, autoNetwork: true},
	{Name: "balanced", For: "A bit of everything. The safe default",
		packets: 1200, newConns: 200, udp: 600, icmp: 60, mbytes: 12, banSeconds: 3600, unaskedReplies: true, autoNetwork: true},
	{Name: "api", For: "Busy web apps and APIs, reverse proxies in front of them",
		packets: 2500, newConns: 500, udp: 800, icmp: 60, mbytes: 24, banSeconds: 1800, unaskedReplies: true, autoNetwork: true},
	{Name: "game", For: "Game and voice servers, where players send a steady stream of small packets",
		packets: 2500, newConns: 250, udp: 2200, icmp: 60, mbytes: 16, banSeconds: 1800, unaskedReplies: true, autoNetwork: false},
	{Name: "database", For: "Database, storage, backup and mail servers with a few heavy clients",
		packets: 4000, newConns: 100, udp: 300, icmp: 40, mbytes: 64, banSeconds: 3600, unaskedReplies: true, autoNetwork: true},
	{Name: "hosting", For: "Machines that carry other people's servers: containers, virtual machines, panels",
		packets: 6000, newConns: 1200, udp: 3000, icmp: 100, mbytes: 64, banSeconds: 1800, unaskedReplies: false, autoNetwork: false},
	{Name: "edge", For: "Very busy front doors: content delivery, large proxies, download servers",
		packets: 12000, newConns: 2500, udp: 5000, icmp: 150, mbytes: 128, banSeconds: 900, unaskedReplies: true, autoNetwork: false},
}

// Level scales a profile to how busy the machine really is.
type Level struct {
	Name  string
	For   string
	Times float64
}

// Levels, from quietest to busiest.
var Levels = []Level{
	{"quiet", "Hardly any visitors. Tightest limits", 0.5},
	{"light", "A small, steady trickle", 0.75},
	{"normal", "Typical for the profile. Start here", 1.0},
	{"busy", "Popular, with regular rush hours", 1.5},
	{"heavy", "Large audience all day", 2.5},
	{"extreme", "As loose as the gate goes", 4.0},
}

// FindProfile looks a profile up by name.
func FindProfile(name string) (Profile, bool) {
	for _, p := range Profiles {
		if p.Name == strings.ToLower(strings.TrimSpace(name)) {
			return p, true
		}
	}
	return Profile{}, false
}

// FindLevel looks a level up by name.
func FindLevel(name string) (Level, bool) {
	for _, l := range Levels {
		if l.Name == strings.ToLower(strings.TrimSpace(name)) {
			return l, true
		}
	}
	return Level{}, false
}

func names[T any](items []T, name func(T) string) string {
	var out []string
	for _, i := range items {
		out = append(out, name(i))
	}
	return strings.Join(out, ", ")
}

func scale(v uint32, times float64, floor uint32) uint32 {
	out := uint32(float64(v)*times + 0.5)
	if out < floor {
		out = floor
	}
	return out
}

// FromProfile builds the full settings for a profile at a level.
func FromProfile(profile, level string) (*Config, error) {
	p, ok := FindProfile(profile)
	if !ok {
		return nil, fmt.Errorf("no profile called %q. Choose from: %s", profile,
			names(Profiles, func(p Profile) string { return p.Name }))
	}
	l, ok := FindLevel(level)
	if !ok {
		return nil, fmt.Errorf("no level called %q. Choose from: %s", level,
			names(Levels, func(l Level) string { return l.Name }))
	}
	t := l.Times
	pps := scale(p.packets, t, 50)

	c := &Config{
		Mode: "auto", Profile: p.Name, Level: l.Name,
		Limits: Limits{
			Packets:        pps,
			Bytes:          uint64(float64(p.mbytes<<20)*t + 0.5),
			TCP:            scale(p.packets, t*0.8, 40),
			UDP:            scale(p.udp, t, 20),
			ICMP:           scale(p.icmp, t, 10),
			NewConnections: scale(p.newConns, t, 10),
		},
		// One broken limit is a warning. Two together, or one broken
		// four times over, crosses the line.
		Scoring: Scoring{Packets: 25, Bytes: 20, TCP: 15, UDP: 20, ICMP: 30, NewConnections: 35, BanAt: 100, Forgive: 10},
		Bans: Bans{
			Seconds:     p.banSeconds,
			RepeatTimes: []uint32{1, 2, 4, 8, 24, 72},
			AutoNetwork: AutoNetwork{Enabled: p.autoNetwork, After: 8, Prefix: 24, Seconds: p.banSeconds * 2},
		},
		Checks: Checks{ImpossibleSenders: true, PrivateSenders: false, BadTCPFlags: true, Fragments: "attack"},
		Reflection: Reflection{
			Enabled:        true,
			UnaskedReplies: p.unaskedReplies,
			Ports: []AmpPort{
				{53, 1233},   // DNS
				{123, 200},   // time servers
				{1900, 200},  // device discovery
				{11211, 100}, // memcached
				{389, 500},   // directory lookups
				{161, 600},   // device monitoring
				{19, 64},     // character generator
				{17, 64},     // quote of the day
			},
		},
		TokenBucket: TokenBucket{Enabled: false, Rate: pps, Burst: pps * 2},
		Attack: Attack{
			SpikePercent: 300, Deviations: 6, MinPackets: scale(p.packets, t*4, 2000),
			TriggerSeconds: 3, RecoverySeconds: 20, MinSeconds: 30,
			TightenPercent: 50, PerAddress: pps,
			NewSendersPerSec: scale(p.newConns, t*2, 100), LimitNewSenders: true,
		},
		Breaker: Breaker{Enabled: true, PacketsPerCPU: 250000, DropPercent: 75},
		Sizes:   Sizes{Addresses: 262144, Bans: 1000000},
	}
	return c, nil
}

// Suggest picks a profile from the services found listening on a machine.
// ports maps "tcp/443"-style names to true.
func Suggest(ports map[string]bool) (string, string) {
	has := func(list ...string) bool {
		for _, p := range list {
			if ports[p] {
				return true
			}
		}
		return false
	}
	switch {
	case has("udp/25565", "tcp/25565", "udp/27015", "tcp/27015", "udp/30120", "tcp/30120", "udp/28015", "udp/7777", "udp/9987", "udp/64738", "udp/19132"):
		return "game", "a game or voice server is listening"
	case has("tcp/2376", "tcp/6443", "tcp/8006", "tcp/2022", "tcp/10250", "tcp/16509"):
		return "hosting", "this machine runs containers or virtual machines for others"
	case has("tcp/3306", "tcp/5432", "tcp/27017", "tcp/6379", "tcp/1433", "tcp/9200", "tcp/25", "tcp/587", "tcp/993"):
		if has("tcp/80", "tcp/443") {
			return "balanced", "a website and a database or mail service share this machine"
		}
		return "database", "a database, storage or mail service is listening"
	case has("tcp/80", "tcp/443", "tcp/8080", "tcp/8443"):
		return "website", "a web server is listening"
	}
	return "balanced", "nothing more specific was found"
}

// PortNames turns a list like ["tcp/443", "udp/53"] into Suggest's map.
func PortNames(list []string) map[string]bool {
	out := map[string]bool{}
	for _, p := range list {
		out[strings.ToLower(strings.TrimSpace(p))] = true
	}
	return out
}

// SortedKeys is a small helper for stable output.
func SortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
