package engine

import (
	"encoding/json"
	"os"
	"time"

	"github.com/RexGuard/SentrAI/gate/internal/config"
	"github.com/RexGuard/SentrAI/gate/internal/kern"
)

// StatusFile is rewritten every second by the running gate.
const StatusFile = config.RunDir + "/status.json"

// PidFile holds the running gate's process number.
const PidFile = config.RunDir + "/pid"

// Status is everything the command line and the live screen show.
type Status struct {
	Version  string         `json:"version"`
	Pid      int            `json:"pid"`
	Iface    string         `json:"interface"`
	Mode     string         `json:"mode"`
	Profile  string         `json:"profile"`
	Level    string         `json:"level"`
	Observe  bool           `json:"observe"`
	Kernel   string         `json:"kernel"`
	Pipeline int            `json:"pipeline_level"`
	Tracking bool           `json:"tracking"`
	Features []kern.Feature `json:"features"`
	Started  time.Time      `json:"started"`
	Updated  time.Time      `json:"updated"`

	Now      Sample              `json:"now"`
	PeakPPS  float64             `json:"peak_pps"`
	PeakBPS  float64             `json:"peak_bps"`
	Normal   float64             `json:"normal_pps"`
	Trigger  float64             `json:"attack_line_pps"`
	Learning bool                `json:"learning"`
	Attack   *AttackRow          `json:"attack,omitempty"`
	Totals   [kern.CMax]kern.Ctr `json:"totals"`
	History  []Point             `json:"history"`

	BanCount     int           `json:"ban_count"`
	NetworkCount int           `json:"network_count"`
	AllowCount   int           `json:"allow_count"`
	Bans         []BanRow      `json:"bans"`
	Events       []EventRow    `json:"events"`
	Attacks      []AttackRow   `json:"attacks"`
	Busiest      []Talker      `json:"busiest"`
	Limits       config.Limits `json:"limits"`
	Problems     []string      `json:"problems,omitempty"`
}

// Point is one second on the graphs.
type Point struct {
	PPS  float64 `json:"p"`
	BPS  float64 `json:"b"`
	Drop float64 `json:"d"`
}

// BanRow is one line of the ban list.
type BanRow struct {
	Target  string    `json:"target"`
	Until   time.Time `json:"until"` // zero = until removed
	Forever bool      `json:"forever,omitempty"`
	Reason  string    `json:"reason"`
	Strikes uint32    `json:"strikes,omitempty"`
}

// EventRow is one line of the event log.
type EventRow struct {
	Time   time.Time `json:"time"`
	Kind   string    `json:"kind"` // ban, network_ban, attack_start, attack_end, start, reload, stop
	Target string    `json:"target,omitempty"`
	Text   string    `json:"text"`
}

// AttackRow is one attack, running or finished.
type AttackRow struct {
	Start   time.Time `json:"start"`
	End     time.Time `json:"end,omitempty"`
	Kind    string    `json:"kind"`
	PeakPPS float64   `json:"peak_pps"`
	PeakBPS float64   `json:"peak_bps"`
	Dropped float64   `json:"dropped"`
	Bans    int       `json:"bans"`
}

// Talker is one of the busiest senders right now.
type Talker struct {
	Addr  string `json:"addr"`
	Pkts  uint32 `json:"pkts"`
	Bytes uint64 `json:"bytes"`
	Score uint32 `json:"score"`
}

// ReadStatus loads the running gate's status. Stale is true when the file
// has not been refreshed for a few seconds (the gate has stopped).
func ReadStatus() (st *Status, stale bool, err error) {
	raw, err := os.ReadFile(StatusFile)
	if err != nil {
		return nil, false, err
	}
	st = &Status{}
	if err := json.Unmarshal(raw, st); err != nil {
		return nil, false, err
	}
	return st, time.Since(st.Updated) > 5*time.Second, nil
}
