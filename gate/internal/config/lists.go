package config

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/RexGuard/SentrAI/gate/internal/kern"
)

// Entry is one line of an allow or block list: an address or a network,
// with an optional note after "#".
type Entry struct {
	Net  netip.Prefix
	Note string
}

func (e Entry) String() string {
	s := e.Net.String()
	if e.Net.IsSingleIP() {
		s = e.Net.Addr().String()
	}
	if e.Note != "" {
		s += "  # " + e.Note
	}
	return s
}

// ReadList reads a list file. A missing file is an empty list. Lines that
// make no sense are returned as problems, not silently skipped.
func ReadList(path string) (entries []Entry, problems []string, err error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	seen := map[netip.Prefix]bool{}
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		note := ""
		if i := strings.IndexByte(line, '#'); i >= 0 {
			note = strings.TrimSpace(line[i+1:])
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		p, perr := kern.ParseTarget(line)
		if perr != nil {
			problems = append(problems, fmt.Sprintf("%s line %d: %v", path, n, perr))
			continue
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		entries = append(entries, Entry{p, note})
	}
	return entries, problems, sc.Err()
}

// WriteList replaces a list file.
func WriteList(path, heading string, entries []Entry) error {
	var b strings.Builder
	b.WriteString("# " + heading + "\n# One address or network per line. Text after # is a note.\n")
	for _, e := range entries {
		b.WriteString(e.String() + "\n")
	}
	return WriteFile(path, []byte(b.String()), 0o644)
}

// AddToList adds or updates an entry. It reports whether the list changed.
func AddToList(path, heading string, e Entry) (bool, error) {
	entries, _, err := ReadList(path)
	if err != nil {
		return false, err
	}
	for i, old := range entries {
		if old.Net == e.Net {
			if old.Note == e.Note || e.Note == "" {
				return false, nil
			}
			entries[i].Note = e.Note
			return true, WriteList(path, heading, entries)
		}
	}
	return true, WriteList(path, heading, append(entries, e))
}

// RemoveFromList removes an entry. It reports whether it was there.
func RemoveFromList(path, heading string, p netip.Prefix) (bool, error) {
	entries, _, err := ReadList(path)
	if err != nil {
		return false, err
	}
	out := entries[:0]
	found := false
	for _, e := range entries {
		if e.Net == p {
			found = true
			continue
		}
		out = append(out, e)
	}
	if !found {
		return false, nil
	}
	return true, WriteList(path, heading, out)
}

// Headings for the two list files.
const (
	AllowHeading = "SentrAI Gate allow list: these senders are never dropped, limited or banned."
	BlockHeading = "SentrAI Gate block list: these senders are always dropped."
)
