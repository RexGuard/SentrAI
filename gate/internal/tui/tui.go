// Package tui draws SentrAI Gate's live screen in a terminal.
package tui

import (
	"fmt"
	"math"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/term"

	"github.com/RexGuard/SentrAI/gate/internal/engine"
	"github.com/RexGuard/SentrAI/gate/internal/kern"
)

const (
	reset  = "\x1b[0m"
	bold   = "\x1b[1m"
	dim    = "\x1b[2m"
	red    = "\x1b[31m"
	green  = "\x1b[32m"
	yellow = "\x1b[33m"
	cyan   = "\x1b[36m"
)

// Tabs of the live screen.
var Tabs = []string{"Overview", "Bans", "Events", "Attacks", "System"}

func visLen(s string) int {
	n, in := 0, false
	for _, r := range s {
		switch {
		case in:
			if r == 'm' {
				in = false
			}
		case r == '\x1b':
			in = true
		default:
			n++
		}
	}
	return n
}

// clipVis cuts a line to w visible characters, keeping colour codes whole.
func clipVis(s string, w int) string {
	if visLen(s) <= w {
		return s
	}
	var b strings.Builder
	n, in := 0, false
	for _, r := range s {
		switch {
		case in:
			in = r != 'm'
		case r == '\x1b':
			in = true
		default:
			if n >= w-1 {
				b.WriteString("…" + reset)
				return b.String()
			}
			n++
		}
		b.WriteRune(r)
	}
	return b.String()
}

func pad(s string, w int) string {
	if n := visLen(s); n < w {
		return s + strings.Repeat(" ", w-n)
	}
	return s
}

func clip(s string, w int) string {
	if utf8.RuneCountInString(s) <= w || w < 2 {
		return s
	}
	return string([]rune(s)[:w-1]) + "…"
}

func bits(bytesPerSec float64) string {
	b := bytesPerSec * 8
	switch {
	case b >= 1e9:
		return fmt.Sprintf("%.2f Gbit/s", b/1e9)
	case b >= 1e6:
		return fmt.Sprintf("%.1f Mbit/s", b/1e6)
	case b >= 1e3:
		return fmt.Sprintf("%.1f Kbit/s", b/1e3)
	}
	return fmt.Sprintf("%.0f bit/s", b)
}

func ago(t time.Time) string {
	d := time.Since(t).Round(time.Second)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return fmt.Sprintf("%dd ago", int(d.Hours()/24))
}

func left(t time.Time, forever bool) string {
	if forever || t.IsZero() {
		return "until removed"
	}
	d := time.Until(t).Round(time.Second)
	if d <= 0 {
		return "ending"
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds left", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm left", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh %dm left", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%dd left", int(d.Hours()/24))
}

// box draws a titled box of fixed inner width.
func box(title string, w int, lines []string) []string {
	out := []string{dim + "┌ " + reset + bold + title + reset + dim + " " + strings.Repeat("─", max(0, w-visLen(title)-2)) + "┐" + reset}
	for _, l := range lines {
		out = append(out, dim+"│"+reset+" "+pad(l, w-1)+dim+"│"+reset)
	}
	return append(out, dim+"└"+strings.Repeat("─", w)+"┘"+reset)
}

func sideBySide(boxes ...[]string) []string {
	rows := 0
	for _, b := range boxes {
		rows = max(rows, len(b))
	}
	out := make([]string, rows)
	for i := range out {
		for _, b := range boxes {
			if i < len(b) {
				out[i] += b[i]
			} else if len(b) > 0 {
				out[i] += strings.Repeat(" ", visLen(b[0]))
			}
		}
	}
	return out
}

var blocks = []rune(" ▁▂▃▄▅▆▇█")

// graph draws the last values as a column chart, rows high.
func graph(vals []float64, w, rows int, colour string, line float64) []string {
	if len(vals) > w {
		vals = vals[len(vals)-w:]
	}
	top := 1.0
	for _, v := range vals {
		top = math.Max(top, v)
	}
	out := make([]string, rows)
	for r := 0; r < rows; r++ {
		var b strings.Builder
		label := ""
		switch r {
		case 0:
			label = engine.Human(top)
		case rows - 1:
			label = "0"
		}
		b.WriteString(dim + fmt.Sprintf("%6s ┤", label) + reset + colour)
		b.WriteString(strings.Repeat(" ", w-len(vals)))
		for _, v := range vals {
			level := v / top * float64(rows*8)
			cell := level - float64((rows-1-r)*8)
			switch {
			case cell >= 8:
				b.WriteRune(blocks[8])
			case cell <= 0:
				if r == rows-1 && v > 0 {
					b.WriteRune(blocks[1])
				} else {
					b.WriteRune(' ')
				}
			default:
				b.WriteRune(blocks[int(math.Ceil(cell))])
			}
		}
		b.WriteString(reset)
		out[r] = b.String()
	}
	return out
}

func state(st *engine.Status, stale bool) string {
	switch {
	case stale:
		return red + bold + "STOPPED" + reset
	case st.Attack != nil:
		return red + bold + "UNDER ATTACK" + reset
	case st.Observe:
		return yellow + bold + "WATCHING ONLY" + reset
	case st.Learning:
		return cyan + bold + "LEARNING" + reset
	}
	return green + bold + "GUARDING" + reset
}

// Render draws one frame as lines of text.
func Render(st *engine.Status, stale bool, tab, w, h int) []string {
	if w < 60 {
		w = 60
	}
	if w > 140 {
		w = 140
	}
	var out []string
	head := fmt.Sprintf(" %sSentrAI Gate%s  %s · %s mode · %s / %s", bold, reset, st.Iface, st.Mode, st.Profile, st.Level)
	s := state(st, stale)
	out = append(out, pad(head, w-visLen(s)-1)+s, "")

	switch tab {
	case 1:
		out = append(out, bansTab(st, w, h)...)
	case 2:
		out = append(out, eventsTab(st, w, h)...)
	case 3:
		out = append(out, attacksTab(st, w)...)
	case 4:
		out = append(out, systemTab(st, w)...)
	default:
		out = append(out, overview(st, w, h)...)
	}

	for len(out) < h-2 {
		out = append(out, "")
	}
	if len(out) > h-2 && h > 4 {
		out = out[:h-2]
	}
	var nav strings.Builder
	nav.WriteString(" ")
	for i, t := range Tabs {
		if i == tab {
			nav.WriteString(fmt.Sprintf("%s[%d] %s%s  ", bold+cyan, i+1, t, reset))
		} else {
			nav.WriteString(fmt.Sprintf("%s[%d] %s%s  ", dim, i+1, t, reset))
		}
	}
	nav.WriteString(dim + "←/→ switch · q quit" + reset)
	out = append(out, "", nav.String())
	for i := range out {
		out[i] = clipVis(out[i], w)
	}
	return out
}

func overview(st *engine.Status, w, h int) []string {
	t := st.Totals
	var dropped, droppedBytes uint64
	for _, slot := range kern.DropSlots {
		dropped += t[slot].Pkts
		droppedBytes += t[slot].Bytes
	}
	seen := t[kern.CSeen].Pkts
	pct := 0.0
	if seen > 0 {
		pct = float64(dropped) / float64(seen) * 100
	}
	bw := (w-1)/3 - 2
	col := func(k, v string) string { return fmt.Sprintf("%-9s %s", k, v) }
	normal := engine.Human(st.Normal) + "/s"
	if st.Learning {
		normal = "learning…"
	}
	dropWord := "Dropped"
	if st.Observe {
		dropWord = "Would drop"
	}
	atk := green + "none" + reset
	if st.Attack != nil {
		atk = red + clip(st.Attack.Kind, bw-12) + reset
	}
	out := sideBySide(
		box("Traffic now", bw, []string{
			col("Packets", engine.Human(st.Now.PPS)+"/s"),
			col("Speed", bits(st.Now.BPS)),
			col("Peak", engine.Human(st.PeakPPS)+"/s"),
			col("Normal", normal),
		}),
		box("Since start", bw, []string{
			col("Seen", engine.Human(float64(seen))),
			col("Passed", engine.Human(float64(seen-min(dropped, seen)))),
			col(dropWord, red+engine.Human(float64(dropped))+reset),
			col("Share", fmt.Sprintf("%.2f%%", pct)),
		}),
		box("Protection", bw, []string{
			col("Banned", fmt.Sprintf("%d addresses", st.BanCount)),
			col("Networks", fmt.Sprintf("%d", st.NetworkCount)),
			col("Allowed", fmt.Sprintf("%d", st.AllowCount)),
			col("Attack", atk),
		}),
	)
	for i := range out {
		out[i] = " " + out[i]
	}

	gw := w - 10
	pps := make([]float64, len(st.History))
	drops := make([]float64, len(st.History))
	for i, p := range st.History {
		pps[i], drops[i] = p.PPS, p.Drop
	}
	rows := 6
	if h < 36 {
		rows = 4
	}
	out = append(out, "", fmt.Sprintf(" %sPackets per second%s  %snow %s · peak %s · normal %s · attack line %s%s",
		bold, reset, dim, engine.Human(st.Now.PPS), engine.Human(st.PeakPPS), engine.Human(st.Normal), engine.Human(st.Trigger), reset))
	out = append(out, graph(pps, gw, rows, cyan, st.Trigger)...)
	out = append(out, "", fmt.Sprintf(" %s%s per second%s  %snow %s%s", bold, dropWord, reset, dim, engine.Human(st.Now.DropPPS), reset))
	out = append(out, graph(drops, gw, 3, red, 0)...)

	out = append(out, "", " "+bold+"Where packets were stopped"+reset)
	any := false
	for _, slot := range kern.DropSlots {
		n := t[slot].Pkts
		if n == 0 {
			continue
		}
		any = true
		share := float64(n) / float64(max(dropped, 1))
		bar := strings.Repeat("█", int(share*30+0.5))
		out = append(out, fmt.Sprintf("   %-20s %8s  %5.1f%%  %s%s%s", kern.SlotName(slot), engine.Human(float64(n)), share*100, red, bar, reset))
	}
	if !any {
		out = append(out, dim+"   Nothing stopped yet."+reset)
	}
	if len(st.Busiest) > 0 && h >= 40 {
		out = append(out, "", " "+bold+"Busiest senders right now"+reset)
		for i, b := range st.Busiest {
			if i >= 5 {
				break
			}
			out = append(out, fmt.Sprintf("   %-40s %8s packets/s   score %d", b.Addr, engine.Human(float64(b.Pkts)), b.Score))
		}
	}
	for _, p := range st.Problems {
		out = append(out, " "+yellow+"! "+clip(p, w-4)+reset)
	}
	return out
}

func bansTab(st *engine.Status, w, h int) []string {
	out := []string{fmt.Sprintf(" %sBanned right now%s  %s%d addresses, %d networks%s", bold, reset, dim, st.BanCount, st.NetworkCount, reset), ""}
	if len(st.Bans) == 0 {
		return append(out, dim+"   Nobody is banned."+reset)
	}
	out = append(out, dim+fmt.Sprintf("   %-40s %-16s %s", "Sender", "Time left", "Why")+reset)
	for i, b := range st.Bans {
		if i >= h-8 {
			out = append(out, dim+fmt.Sprintf("   … and more. See all: sentrai-gate bans")+reset)
			break
		}
		why := b.Reason
		if b.Strikes > 1 {
			why += fmt.Sprintf(" (strike %d)", b.Strikes)
		}
		out = append(out, fmt.Sprintf("   %-40s %-16s %s", b.Target, left(b.Until, b.Forever), clip(why, max(10, w-62))))
	}
	return out
}

func eventsTab(st *engine.Status, w, h int) []string {
	out := []string{" " + bold + "What happened" + reset + dim + "  newest first" + reset, ""}
	if len(st.Events) == 0 {
		return append(out, dim+"   Nothing yet."+reset)
	}
	for i := len(st.Events) - 1; i >= 0 && len(out) < h-4; i-- {
		ev := st.Events[i]
		colour := ""
		switch ev.Kind {
		case "attack_start", "network_ban":
			colour = red
		case "ban":
			colour = yellow
		case "attack_end":
			colour = green
		}
		out = append(out, fmt.Sprintf("   %s%s%s  %s%s%s", dim, ev.Time.Local().Format("15:04:05"), reset, colour, clip(ev.Text, w-15), reset))
	}
	return out
}

func attacksTab(st *engine.Status, w int) []string {
	out := []string{" " + bold + "Attacks" + reset + dim + "  newest first" + reset, ""}
	if st.Attack != nil {
		a := st.Attack
		out = append(out, fmt.Sprintf("   %sNOW%s  %s · started %s · peak %s packets/s (%s) · %s dropped · %d banned", red+bold, reset,
			a.Kind, ago(a.Start), engine.Human(a.PeakPPS), bits(a.PeakBPS), engine.Human(a.Dropped), a.Bans), "")
	}
	if len(st.Attacks) == 0 && st.Attack == nil {
		return append(out, dim+"   No attacks seen."+reset)
	}
	for i := len(st.Attacks) - 1; i >= 0; i-- {
		a := st.Attacks[i]
		out = append(out, fmt.Sprintf("   %s  %-24s lasted %-8s peak %s packets/s (%s) · %s dropped · %d banned",
			a.Start.Local().Format("2 Jan 15:04"), a.Kind, a.End.Sub(a.Start).Round(time.Second),
			engine.Human(a.PeakPPS), bits(a.PeakBPS), engine.Human(a.Dropped), a.Bans))
	}
	return out
}

func systemTab(st *engine.Status, w int) []string {
	out := []string{" " + bold + "This machine" + reset, "",
		fmt.Sprintf("   Version     %s", st.Version),
		fmt.Sprintf("   Kernel      %s", st.Kernel),
		fmt.Sprintf("   Interface   %s (%s mode)", st.Iface, st.Mode),
		fmt.Sprintf("   Running     since %s (%s)", st.Started.Local().Format("2 Jan 15:04"), ago(st.Started)),
		"", " " + bold + "What the kernel offers" + reset, ""}
	for _, f := range st.Features {
		mark := green + "✓" + reset
		if !f.On {
			mark = yellow + "–" + reset
		}
		out = append(out, fmt.Sprintf("   %s %s", mark, f.Name))
		if f.Note != "" {
			out = append(out, dim+"       "+clip(f.Note, w-8)+reset)
		}
	}
	l := st.Limits
	out = append(out, "", " "+bold+"Limits per sender, per second"+reset, "",
		fmt.Sprintf("   Packets %d · TCP %d · UDP %d · ICMP %d · new connections %d · data %s",
			l.Packets, l.TCP, l.UDP, l.ICMP, l.NewConnections, bits(float64(l.Bytes))))
	if st.Attack != nil {
		out = append(out, dim+"   Tightened while under attack."+reset)
	}
	return out
}

// Print writes lines to the terminal, without colour codes when the output
// goes to a file or another program, and without the blank filler rows.
func Print(lines []string) {
	plain := !term.IsTerminal(int(os.Stdout.Fd()))
	blank := 0
	for _, l := range lines {
		l = strings.TrimRight(l, " ")
		if plain {
			l = stripColour(l)
		}
		if l == "" {
			blank++
			if blank > 1 {
				continue
			}
		} else {
			blank = 0
		}
		fmt.Println(l)
	}
}

func stripColour(s string) string {
	var b strings.Builder
	in := false
	for _, r := range s {
		switch {
		case in:
			in = r != 'm'
		case r == '\x1b':
			in = true
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Run shows the live screen until the user quits.
func Run() error {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return fmt.Errorf("the live screen needs a terminal. For a one-off summary run: sentrai-gate status")
	}
	if _, _, err := engine.ReadStatus(); err != nil {
		return fmt.Errorf("the gate is not running. Start it with: sudo systemctl start sentrai-gate")
	}
	old, err := term.MakeRaw(fd)
	if err != nil {
		return err
	}
	fmt.Print("\x1b[?1049h\x1b[?25l")
	defer func() {
		fmt.Print("\x1b[?25h\x1b[?1049l")
		_ = term.Restore(fd, old)
	}()

	keys := make(chan []byte, 8)
	go func() {
		for {
			buf := make([]byte, 8)
			n, err := os.Stdin.Read(buf)
			if err != nil {
				close(keys)
				return
			}
			keys <- buf[:n]
		}
	}()

	tab := 0
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	draw := func() {
		w, h, err := term.GetSize(fd)
		if err != nil {
			w, h = 100, 40
		}
		st, stale, err := engine.ReadStatus()
		if err != nil {
			st, stale = &engine.Status{}, true
		}
		var b strings.Builder
		b.WriteString("\x1b[H")
		for _, l := range Render(st, stale, tab, w, h) {
			b.WriteString(l + "\x1b[K\r\n")
		}
		b.WriteString("\x1b[J")
		fmt.Print(b.String())
	}
	draw()
	for {
		select {
		case <-tick.C:
			draw()
		case k, ok := <-keys:
			if !ok {
				return nil
			}
			switch {
			case len(k) == 1 && (k[0] == 'q' || k[0] == 3 || k[0] == 27):
				return nil
			case len(k) == 1 && k[0] >= '1' && int(k[0]-'1') < len(Tabs):
				tab = int(k[0] - '1')
			case len(k) == 1 && k[0] == '\t', len(k) == 3 && k[2] == 'C':
				tab = (tab + 1) % len(Tabs)
			case len(k) == 3 && k[2] == 'D':
				tab = (tab + len(Tabs) - 1) % len(Tabs)
			}
			draw()
		}
	}
}
