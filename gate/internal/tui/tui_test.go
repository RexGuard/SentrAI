package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/RexGuard/SentrAI/gate/internal/engine"
	"github.com/RexGuard/SentrAI/gate/internal/kern"
)

func sample() *engine.Status {
	st := &engine.Status{
		Version: "test", Iface: "eth0", Mode: "native", Profile: "game", Level: "busy",
		Started: time.Now().Add(-time.Hour), Updated: time.Now(),
		Now: engine.Sample{PPS: 1234, BPS: 2e6, DropPPS: 200}, PeakPPS: 9000, Normal: 800, Trigger: 5000,
		BanCount: 2, NetworkCount: 1, AllowCount: 3,
		Bans: []engine.BanRow{{Target: "1.2.3.4", Until: time.Now().Add(time.Hour), Reason: "packets over the limit", Strikes: 2},
			{Target: "5.6.7.0/24", Forever: true, Reason: "added by hand"}},
		Events:   []engine.EventRow{{Time: time.Now(), Kind: "ban", Text: "Banned 1.2.3.4 for 1h0m0s"}},
		Attacks:  []engine.AttackRow{{Start: time.Now().Add(-2 * time.Hour), End: time.Now().Add(-time.Hour), Kind: "UDP flood", PeakPPS: 90000}},
		Features: []kern.Feature{{Name: "Full pipeline", On: true}, {Name: "Fastest mode", On: false, Note: "driver does not offer it"}},
		Busiest:  []engine.Talker{{Addr: "9.9.9.9", Pkts: 400, Score: 25}},
	}
	st.Totals[kern.CSeen].Pkts = 1000
	st.Totals[kern.CDropBanned].Pkts = 60
	st.Totals[kern.CDropAmp].Pkts = 40
	for i := 0; i < 400; i++ {
		st.History = append(st.History, engine.Point{PPS: float64(i * 10), Drop: float64(i)})
	}
	return st
}

func TestEveryTabDrawsAndFits(t *testing.T) {
	st := sample()
	wants := []string{"Where packets were stopped", "1.2.3.4", "Banned 1.2.3.4", "UDP flood", "What the kernel offers"}
	for tab := range Tabs {
		for _, size := range [][2]int{{60, 20}, {100, 34}, {200, 60}} {
			lines := Render(st, false, tab, size[0], size[1])
			if len(lines) > size[1] {
				t.Errorf("tab %d at %v: %d lines do not fit", tab, size, len(lines))
			}
			for _, l := range lines {
				if visLen(l) > min(max(size[0], 60), 140) {
					t.Errorf("tab %d at %v: line too wide (%d): %q", tab, size, visLen(l), stripColour(l))
				}
			}
			if size[0] == 100 && !strings.Contains(strings.Join(lines, "\n"), wants[tab]) {
				t.Errorf("tab %d is missing %q", tab, wants[tab])
			}
		}
	}
}

func TestStateWords(t *testing.T) {
	st := sample()
	check := func(want string, stale bool) {
		t.Helper()
		if got := stripColour(Render(st, stale, 0, 100, 34)[0]); !strings.HasSuffix(got, want) {
			t.Errorf("header %q should end with %q", got, want)
		}
	}
	check("GUARDING", false)
	st.Observe = true
	check("WATCHING ONLY", false)
	st.Attack = &engine.AttackRow{Kind: "UDP flood", Start: time.Now()}
	check("UNDER ATTACK", false)
	check("STOPPED", true)
	// An empty status (gate just stopped) must not crash the screen.
	Render(&engine.Status{}, true, 0, 80, 24)
}
