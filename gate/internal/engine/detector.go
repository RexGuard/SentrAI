// Package engine is the part of SentrAI Gate that runs beside the kernel
// filter: it learns what normal traffic looks like, decides when the
// machine is under attack, keeps the ban lists tidy and writes the status
// the live screen shows.
package engine

import (
	"math"
	"time"

	"github.com/RexGuard/SentrAI/gate/internal/config"
)

// Sample is one second of traffic, per second rates.
type Sample struct {
	PPS, BPS            float64
	TCP, UDP, ICMP, SYN float64
	DropPPS, DropBPS    float64
	AmpDrops            float64
	NewSenders          float64
}

// Detector learns the normal traffic level as a moving average that leans
// on recent seconds (an exponentially weighted moving average) and calls an
// attack when traffic stays far above it.
type Detector struct {
	cfg config.Attack

	Mean    float64   `json:"mean"`    // learned normal packets per second
	Var     float64   `json:"var"`     // how much normal traffic wobbles
	Samples int       `json:"samples"` // seconds learned so far
	Fast    float64   `json:"-"`       // smoothed current rate
	Active  bool      `json:"-"`
	Since   time.Time `json:"-"`
	PeakPPS float64   `json:"-"`
	PeakBPS float64   `json:"-"`
	Kind    string    `json:"-"`
	Dropped float64   `json:"-"`

	over, under int
}

const (
	slowAlpha = 1.0 / 300 // normal level remembers about five minutes
	fastAlpha = 0.5
	warmup    = 20 // seconds of learning before the first attack call
)

// NewDetector makes a detector with nothing learned.
func NewDetector(cfg config.Attack) *Detector { return &Detector{cfg: cfg} }

// SetConfig swaps the settings and keeps what was learned.
func (d *Detector) SetConfig(cfg config.Attack) { d.cfg = cfg }

// Trigger is the packets-per-second level that counts as an attack right
// now. It is the highest of three lines: the fixed floor from the
// settings, the learned normal plus the spike percentage, and the learned
// normal plus several times its usual wobble.
func (d *Detector) Trigger() float64 {
	t := float64(d.cfg.MinPackets)
	if spike := d.Mean * (1 + float64(d.cfg.SpikePercent)/100); spike > t {
		t = spike
	}
	if dev := d.Mean + d.cfg.Deviations*math.Sqrt(d.Var); dev > t {
		t = dev
	}
	return t
}

// Learning says whether the detector is still in its first seconds.
func (d *Detector) Learning() bool { return d.Samples < warmup }

// Tick feeds one second of traffic. It reports whether an attack just
// started or just ended.
func (d *Detector) Tick(s Sample, now time.Time) (started, ended bool) {
	if d.Samples == 0 {
		d.Fast = s.PPS
	} else {
		d.Fast += fastAlpha * (s.PPS - d.Fast)
	}
	trigger := d.Trigger()

	if d.Active {
		if s.PPS > d.PeakPPS {
			d.PeakPPS = s.PPS
		}
		if s.BPS > d.PeakBPS {
			d.PeakBPS = s.BPS
		}
		d.Dropped += s.DropPPS
		d.Kind = classify(s, d.Kind)
		if d.Fast < trigger*0.7 {
			d.under++
		} else {
			d.under = 0
		}
		if d.under >= d.cfg.RecoverySeconds && now.Sub(d.Since) >= time.Duration(d.cfg.MinSeconds)*time.Second {
			d.Active = false
			d.over, d.under = 0, 0
			return false, true
		}
		return false, false
	}

	// Starting an attack call needs every one of the last few seconds to
	// be over the line, so a one-second blip never counts.
	if s.PPS > trigger {
		d.over++
	} else {
		d.over = 0
		// Only calm seconds teach the normal level, so an attack (or its
		// slow build-up past the line) can never raise it.
		alpha := slowAlpha
		if a := 1.0 / float64(d.Samples+1); a > alpha {
			alpha = a
		}
		// One second can only teach so much: a steady climb toward the
		// line cannot drag the normal level (and the line) up with it.
		x := s.PPS
		if !d.Learning() && x > d.Mean*1.5+100 {
			x = d.Mean*1.5 + 100
		}
		diff := x - d.Mean
		d.Mean += alpha * diff
		d.Var = (1 - alpha) * (d.Var + alpha*diff*diff)
		d.Samples++
	}
	if d.over >= d.cfg.TriggerSeconds && !d.Learning() {
		d.Active = true
		d.Since = now
		d.PeakPPS, d.PeakBPS, d.Dropped = s.PPS, s.BPS, s.DropPPS
		d.Kind = classify(s, "")
		d.under = 0
		return true, false
	}
	return false, false
}

// classify names the attack from what the traffic is mostly made of.
func classify(s Sample, before string) string {
	if s.PPS <= 0 {
		return before
	}
	kind := "Mixed flood"
	switch {
	case s.AmpDrops > s.PPS*0.4:
		kind = "Amplified replies"
	case s.SYN > s.PPS*0.5:
		kind = "Connection flood (SYN)"
	case s.UDP > s.PPS*0.6:
		kind = "UDP flood"
	case s.ICMP > s.PPS*0.5:
		kind = "Ping flood (ICMP)"
	case s.TCP > s.PPS*0.6:
		kind = "TCP flood"
	}
	if before != "" && before != kind && before != "Mixed flood" && kind != "Mixed flood" {
		return "Mixed flood"
	}
	if kind == "Mixed flood" && before != "" {
		return before
	}
	return kind
}
