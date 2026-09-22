package nagios

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// Range is a Nagios threshold range. An alert is raised when the checked
// value lies outside [Start, End], or inside it if Inside is set
// (the "@" prefix in range syntax).
type Range struct {
	Start  float64
	End    float64
	Inside bool

	raw string
}

// ParseRange parses Nagios range syntax:
//
//	"10"     -> alert if value < 0 or > 10
//	"10:"    -> alert if value < 10
//	"~:10"   -> alert if value > 10
//	"10:20"  -> alert if value < 10 or > 20
//	"@10:20" -> alert if 10 <= value <= 20
func ParseRange(s string) (*Range, error) {
	r := &Range{Start: 0, End: math.Inf(1), raw: s}
	spec := s
	if strings.HasPrefix(spec, "@") {
		r.Inside = true
		spec = spec[1:]
	}
	if spec == "" {
		return nil, fmt.Errorf("empty range %q", s)
	}

	start, end, hasColon := strings.Cut(spec, ":")
	if !hasColon {
		v, err := strconv.ParseFloat(spec, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid range %q: %v", s, err)
		}
		r.End = v
		return r, nil
	}

	switch start {
	case "~":
		r.Start = math.Inf(-1)
	case "":
		r.Start = 0
	default:
		v, err := strconv.ParseFloat(start, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid range start %q: %v", s, err)
		}
		r.Start = v
	}

	if end != "" {
		v, err := strconv.ParseFloat(end, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid range end %q: %v", s, err)
		}
		r.End = v
	}

	if r.Start > r.End {
		return nil, fmt.Errorf("invalid range %q: start greater than end", s)
	}
	return r, nil
}

// ParseLifetime parses a threshold for "seconds remaining" values. A bare
// number N is shorthand for the range "N:" (alert when the value drops
// below N) — the plain Nagios bare-number semantics ("alert if outside
// 0..N") point the wrong way for lifetimes. Strings containing range
// syntax (":", "@", "~") are parsed as-is.
func ParseLifetime(s string) (*Range, error) {
	if !strings.ContainsAny(s, ":@~") {
		if _, err := strconv.ParseFloat(s, 64); err != nil {
			return nil, fmt.Errorf("invalid threshold %q: %v", s, err)
		}
		return ParseRange(s + ":")
	}
	return ParseRange(s)
}

// Violated reports whether v triggers an alert for this range.
func (r *Range) Violated(v float64) bool {
	inside := v >= r.Start && v <= r.End
	if r.Inside {
		return inside
	}
	return !inside
}

// String returns the original range specification, for perfdata output.
func (r *Range) String() string {
	if r == nil {
		return ""
	}
	return r.raw
}
