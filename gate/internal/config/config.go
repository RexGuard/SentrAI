// Package config holds SentrAI Gate's settings: the file format, the
// ready-made profiles, and the allow / block list files.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/RexGuard/SentrAI/gate/internal/kern"
)

// Where things live on an installed machine.
const (
	Dir       = "/etc/sentrai-gate"
	File      = Dir + "/config.yaml"
	AllowFile = Dir + "/allow.list"
	BlockFile = Dir + "/block.list"
	StateDir  = "/var/lib/sentrai-gate"
	RunDir    = "/run/sentrai-gate"
	LogDir    = "/var/log/sentrai-gate"
)

// Config is the whole settings file. Everything except interface, profile
// and level is optional: what is left out comes from the profile.
type Config struct {
	Interface string `yaml:"interface"`
	Mode      string `yaml:"mode"`
	Observe   bool   `yaml:"observe"`
	Profile   string `yaml:"profile"`
	Level     string `yaml:"level"`

	Limits      Limits      `yaml:"limits"`
	Scoring     Scoring     `yaml:"scoring"`
	Bans        Bans        `yaml:"bans"`
	Checks      Checks      `yaml:"checks"`
	Reflection  Reflection  `yaml:"reflection"`
	TokenBucket TokenBucket `yaml:"token_bucket"`
	Attack      Attack      `yaml:"attack"`
	Breaker     Breaker     `yaml:"breaker"`
	Sizes       Sizes       `yaml:"sizes"`
}

// Limits are per sending address, per second.
type Limits struct {
	Packets        uint32 `yaml:"packets"`
	Bytes          uint64 `yaml:"bytes"`
	TCP            uint32 `yaml:"tcp_packets"`
	UDP            uint32 `yaml:"udp_packets"`
	ICMP           uint32 `yaml:"icmp_packets"`
	NewConnections uint32 `yaml:"new_connections"`
}

// Scoring is how many points each broken limit costs, and where the ban is.
type Scoring struct {
	Packets        uint32 `yaml:"packets"`
	Bytes          uint32 `yaml:"bytes"`
	TCP            uint32 `yaml:"tcp_packets"`
	UDP            uint32 `yaml:"udp_packets"`
	ICMP           uint32 `yaml:"icmp_packets"`
	NewConnections uint32 `yaml:"new_connections"`
	BanAt          uint32 `yaml:"ban_at"`
	Forgive        uint32 `yaml:"forgive_per_second"`
}

// Bans says how long, and when a whole network goes.
type Bans struct {
	Seconds     uint32      `yaml:"seconds"`
	RepeatTimes []uint32    `yaml:"repeat_times"`
	AutoNetwork AutoNetwork `yaml:"auto_network"`
}

// AutoNetwork bans a whole IPv4 network once enough of it is banned.
type AutoNetwork struct {
	Enabled bool   `yaml:"enabled"`
	After   int    `yaml:"after"`
	Prefix  int    `yaml:"prefix"`
	Seconds uint32 `yaml:"seconds"`
}

// Checks are the "cannot be real" tests.
type Checks struct {
	ImpossibleSenders bool   `yaml:"impossible_senders"`
	PrivateSenders    bool   `yaml:"private_senders"`
	BadTCPFlags       bool   `yaml:"bad_tcp_flags"`
	Fragments         string `yaml:"fragments"` // pass | drop | attack
}

// Reflection is the filter for replies nobody asked for.
type Reflection struct {
	Enabled        bool      `yaml:"enabled"`
	UnaskedReplies bool      `yaml:"unasked_replies"`
	Ports          []AmpPort `yaml:"ports"`
}

// AmpPort is a service often abused to bounce big replies at a victim.
type AmpPort struct {
	Port     uint16 `yaml:"port"`
	MinBytes uint16 `yaml:"min_bytes"`
}

// TokenBucket is an optional smooth per-address limiter.
type TokenBucket struct {
	Enabled bool   `yaml:"enabled"`
	Rate    uint32 `yaml:"rate"`
	Burst   uint32 `yaml:"burst"`
}

// Attack controls when the gate decides the machine is under attack, and
// how much stricter it gets.
type Attack struct {
	SpikePercent     uint32  `yaml:"spike_percent"`
	Deviations       float64 `yaml:"deviations"`
	MinPackets       uint32  `yaml:"min_packets"`
	TriggerSeconds   int     `yaml:"trigger_seconds"`
	RecoverySeconds  int     `yaml:"recovery_seconds"`
	MinSeconds       int     `yaml:"min_seconds"`
	TightenPercent   uint32  `yaml:"tighten_percent"`
	PerAddress       uint32  `yaml:"per_address_packets"`
	NewSendersPerSec uint32  `yaml:"new_senders_per_second"`
	LimitNewSenders  bool    `yaml:"limit_new_senders"`
}

// Breaker sheds load when a CPU is swamped.
type Breaker struct {
	Enabled       bool   `yaml:"enabled"`
	PacketsPerCPU uint32 `yaml:"packets_per_cpu"`
	DropPercent   uint32 `yaml:"drop_percent"`
}

// Sizes are how many addresses the gate can remember.
type Sizes struct {
	Addresses uint32 `yaml:"addresses"`
	Bans      uint32 `yaml:"bans"`
}

// Load reads the settings file. Values missing from the file come from
// the profile it names.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(raw)
}

// Parse is Load for settings already in memory.
func Parse(raw []byte) (*Config, error) {
	var head struct {
		Profile string `yaml:"profile"`
		Level   string `yaml:"level"`
	}
	if err := yaml.Unmarshal(raw, &head); err != nil {
		return nil, fmt.Errorf("settings file is not valid: %w", err)
	}
	if head.Profile == "" {
		head.Profile = "balanced"
	}
	if head.Level == "" {
		head.Level = "normal"
	}
	c, err := FromProfile(head.Profile, head.Level)
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(raw, c); err != nil {
		return nil, fmt.Errorf("settings file is not valid: %w", err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Validate checks the settings make sense and fixes harmless slips.
func (c *Config) Validate() error {
	var problems []string
	bad := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }

	switch c.Mode {
	case "":
		c.Mode = "auto"
	case "auto", "native", "generic":
	default:
		bad("mode must be auto, native or generic, not %q", c.Mode)
	}
	switch c.Checks.Fragments {
	case "":
		c.Checks.Fragments = "attack"
	case "pass", "drop", "attack":
	default:
		bad("checks.fragments must be pass, drop or attack, not %q", c.Checks.Fragments)
	}
	if c.Limits.Packets == 0 {
		bad("limits.packets must be above 0")
	}
	if c.Scoring.BanAt == 0 {
		bad("scoring.ban_at must be above 0")
	}
	if c.Bans.Seconds == 0 || c.Bans.Seconds > 30*86400 {
		bad("bans.seconds must be between 1 and 2592000 (30 days)")
	}
	if len(c.Bans.RepeatTimes) == 0 {
		c.Bans.RepeatTimes = []uint32{1}
	}
	if len(c.Bans.RepeatTimes) > 8 {
		bad("bans.repeat_times takes at most 8 steps")
	}
	for _, m := range c.Bans.RepeatTimes {
		if m == 0 || m > 1000 {
			bad("bans.repeat_times values must be between 1 and 1000")
			break
		}
	}
	if len(c.Reflection.Ports) > 8 {
		bad("reflection.ports takes at most 8 entries")
	}
	if c.Bans.AutoNetwork.Enabled {
		if c.Bans.AutoNetwork.Prefix < 16 || c.Bans.AutoNetwork.Prefix > 30 {
			bad("bans.auto_network.prefix must be between 16 and 30")
		}
		if c.Bans.AutoNetwork.After < 2 {
			bad("bans.auto_network.after must be at least 2")
		}
	}
	if c.Attack.TightenPercent == 0 || c.Attack.TightenPercent > 100 {
		bad("attack.tighten_percent must be between 1 and 100")
	}
	if c.Attack.TriggerSeconds < 1 {
		c.Attack.TriggerSeconds = 1
	}
	if c.Attack.RecoverySeconds < 1 {
		c.Attack.RecoverySeconds = 1
	}
	if c.Breaker.DropPercent > 100 {
		bad("breaker.drop_percent must be between 0 and 100")
	}
	if c.TokenBucket.Enabled && (c.TokenBucket.Rate == 0 || c.TokenBucket.Burst == 0) {
		bad("token_bucket needs both rate and burst when it is on")
	}
	if c.Sizes.Addresses != 0 && c.Sizes.Addresses < 1024 {
		bad("sizes.addresses must be at least 1024")
	}
	if len(problems) > 0 {
		return errors.New("settings problem: " + strings.Join(problems, "; "))
	}
	return nil
}

// Kernel turns the settings into what the packet filter reads. hasAllow
// and hasSubnets say whether those lists have anything in them; tracking
// and attack are the live state.
func (c *Config) Kernel(hasAllow, hasSubnets, tracking, attack bool) kern.Cfg {
	k := kern.Cfg{
		Bps: c.Limits.Bytes, Pps: c.Limits.Packets, TcpPps: c.Limits.TCP,
		UdpPps: c.Limits.UDP, IcmpPps: c.Limits.ICMP, SynPps: c.Limits.NewConnections,
		S_pps: c.Scoring.Packets, S_bps: c.Scoring.Bytes, S_tcp: c.Scoring.TCP,
		S_udp: c.Scoring.UDP, S_icmp: c.Scoring.ICMP, S_syn: c.Scoring.NewConnections,
		ScoreBan: c.Scoring.BanAt, ScoreDecay: c.Scoring.Forgive, BanSecs: c.Bans.Seconds,
		AttackPct: c.Attack.TightenPercent, AttackIpPps: c.Attack.PerAddress,
		PanicPps: c.Breaker.PacketsPerCPU, PanicDropPct: c.Breaker.DropPercent,
	}
	set := func(on bool, f uint32) {
		if on {
			k.Flags |= f
		}
	}
	k.Flags = kern.FEnabled | kern.FRate
	set(c.Observe, kern.FObserve)
	set(c.Checks.ImpossibleSenders, kern.FDropBogon)
	set(c.Checks.PrivateSenders, kern.FDropPrivate)
	set(c.Checks.BadTCPFlags, kern.FDropBadTCP)
	set(c.Checks.Fragments == "drop", kern.FDropFrags)
	set(c.Checks.Fragments == "attack", kern.FDropFragsAttack)
	set(c.Reflection.Enabled, kern.FAmp)
	set(c.Reflection.Enabled && c.Reflection.UnaskedReplies, kern.FReflect)
	set(c.TokenBucket.Enabled, kern.FToken)
	set(c.Attack.LimitNewSenders, kern.FNewSrc)
	set(c.Breaker.Enabled, kern.FPanic)
	set(hasAllow, kern.FHasAllow)
	set(hasSubnets, kern.FHasSubnets)
	set(tracking, kern.FTrack)
	set(attack, kern.FAttack)

	last := uint32(1)
	for i := range k.StrikeMult {
		if i < len(c.Bans.RepeatTimes) {
			last = c.Bans.RepeatTimes[i]
		}
		k.StrikeMult[i] = last
	}
	for i, p := range c.Reflection.Ports {
		if i >= len(k.AmpPort) {
			break
		}
		k.AmpPort[i], k.AmpMin[i] = p.Port, p.MinBytes
	}
	if c.TokenBucket.Enabled {
		k.TokenRate, k.TokenBurst = c.TokenBucket.Rate, c.TokenBucket.Burst
	}
	// The kernel counts new senders per CPU.
	cpus := uint32(runtime.NumCPU())
	k.NewsrcLimit = c.Attack.NewSendersPerSec / cpus
	if k.NewsrcLimit == 0 && c.Attack.NewSendersPerSec > 0 {
		k.NewsrcLimit = 1
	}
	return k
}

// Render writes a fresh, commented settings file for a profile.
func Render(iface, profile, level string, observe bool) (string, error) {
	c, err := FromProfile(profile, level)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, `# SentrAI Gate settings.
# After a change:  sudo sentrai-gate reload

# The network card that faces the internet.
interface: %s

# auto tries the fastest mode first and steps down by itself.
mode: auto

# true = watch only. Counts what would be dropped, drops nothing.
observe: %t

# What this machine is for, and how busy it is. See: sentrai-gate profile list
profile: %s
level: %s

# Everything below is optional. The profile already sets it. Remove the "#"
# from a line to set your own value. These are the profile's values:
#
`, iface, observe, profile, level)
	rest := *c
	body, err := yaml.Marshal(struct {
		Limits      Limits      `yaml:"limits"`
		Scoring     Scoring     `yaml:"scoring"`
		Bans        Bans        `yaml:"bans"`
		Checks      Checks      `yaml:"checks"`
		Reflection  Reflection  `yaml:"reflection"`
		TokenBucket TokenBucket `yaml:"token_bucket"`
		Attack      Attack      `yaml:"attack"`
		Breaker     Breaker     `yaml:"breaker"`
		Sizes       Sizes       `yaml:"sizes"`
	}{rest.Limits, rest.Scoring, rest.Bans, rest.Checks, rest.Reflection, rest.TokenBucket, rest.Attack, rest.Breaker, rest.Sizes})
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(strings.TrimRight(string(body), "\n"), "\n") {
		b.WriteString("# " + line + "\n")
	}
	return b.String(), nil
}

// WriteFile writes data so a reader never sees half a file.
func WriteFile(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
