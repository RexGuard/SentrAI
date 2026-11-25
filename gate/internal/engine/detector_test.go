package engine

import (
	"testing"
	"time"

	"github.com/RexGuard/SentrAI/gate/internal/config"
)

func attackCfg() config.Attack {
	c, _ := config.FromProfile("balanced", "normal")
	return c.Attack
}

func feed(d *Detector, at *time.Time, n int, s Sample) (started, ended int) {
	for i := 0; i < n; i++ {
		*at = at.Add(time.Second)
		st, en := d.Tick(s, *at)
		if st {
			started++
		}
		if en {
			ended++
		}
	}
	return
}

func TestLearnsNormalThenCallsAttack(t *testing.T) {
	d := NewDetector(attackCfg())
	at := time.Unix(1_800_000_000, 0)

	if s, _ := feed(d, &at, 120, Sample{PPS: 1000, TCP: 900}); s != 0 {
		t.Fatal("steady traffic must not be called an attack")
	}
	if d.Mean < 950 || d.Mean > 1050 {
		t.Fatalf("learned normal = %.0f, want about 1000", d.Mean)
	}
	line := d.Trigger()
	if line < 4000 {
		t.Fatalf("attack line = %.0f, should sit well above normal", line)
	}

	// A short blip is not an attack.
	if s, _ := feed(d, &at, 1, Sample{PPS: 50000, SYN: 50000}); s != 0 {
		t.Error("a one-second blip must not be called an attack")
	}
	feed(d, &at, 10, Sample{PPS: 1000})

	s, _ := feed(d, &at, 10, Sample{PPS: 60000, SYN: 58000, TCP: 58000, DropPPS: 50000})
	if s != 1 || !d.Active {
		t.Fatalf("a sustained flood must be called an attack once, got %d", s)
	}
	if d.Kind != "Connection flood (SYN)" {
		t.Errorf("kind = %q", d.Kind)
	}
	if d.Mean > 1100 {
		t.Errorf("the flood taught the normal level: %.0f", d.Mean)
	}

	// Ends only after staying calm, and not before the minimum length.
	_, e := feed(d, &at, 10, Sample{PPS: 1000})
	if e != 0 {
		t.Error("attack ended before the calm period was over")
	}
	_, e = feed(d, &at, 30, Sample{PPS: 1000})
	if e != 1 || d.Active {
		t.Errorf("attack should have ended once, got %d", e)
	}
}

func TestNoAttackCallWhileStillLearning(t *testing.T) {
	d := NewDetector(attackCfg())
	at := time.Unix(1_800_000_000, 0)
	if s, _ := feed(d, &at, 10, Sample{PPS: 90000, UDP: 90000}); s != 0 {
		t.Error("the first seconds after start must not raise an attack")
	}
}

func TestSlowRampCannotTrainTheLineUp(t *testing.T) {
	d := NewDetector(attackCfg())
	at := time.Unix(1_800_000_000, 0)
	feed(d, &at, 60, Sample{PPS: 500})
	started := 0
	for pps := 500.0; pps < 200000; pps *= 1.05 {
		s, _ := feed(d, &at, 1, Sample{PPS: pps, UDP: pps})
		started += s
	}
	if started != 1 {
		t.Errorf("a slow ramp should still be caught once, got %d (normal now %.0f)", started, d.Mean)
	}
}

func TestClassify(t *testing.T) {
	cases := map[string]Sample{
		"UDP flood":         {PPS: 1000, UDP: 900},
		"Ping flood (ICMP)": {PPS: 1000, ICMP: 800},
		"Amplified replies": {PPS: 1000, UDP: 950, AmpDrops: 700},
		"TCP flood":         {PPS: 1000, TCP: 900, SYN: 10},
		"Mixed flood":       {PPS: 1000, TCP: 300, UDP: 300, ICMP: 300},
	}
	for want, s := range cases {
		if got := classify(s, ""); got != want {
			t.Errorf("%+v: %q, want %q", s, got, want)
		}
	}
	if got := classify(Sample{PPS: 1000, UDP: 900}, "Connection flood (SYN)"); got != "Mixed flood" {
		t.Errorf("an attack that changes shape should read as mixed, got %q", got)
	}
}
