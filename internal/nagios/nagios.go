// Package nagios implements Nagios plugin output formatting: exit statuses,
// performance data and threshold ranges per the Nagios plugin development
// guidelines (https://nagios-plugins.org/doc/guidelines.html).
package nagios

import (
	"fmt"
	"strings"
)

// Status is a Nagios plugin exit status.
type Status int

const (
	OK       Status = 0
	Warning  Status = 1
	Critical Status = 2
	Unknown  Status = 3
)

func (s Status) String() string {
	switch s {
	case OK:
		return "OK"
	case Warning:
		return "WARNING"
	case Critical:
		return "CRITICAL"
	case Unknown:
		return "UNKNOWN"
	}
	return fmt.Sprintf("Status(%d)", int(s))
}

// severity rank for aggregation: OK < Unknown < Warning < Critical,
// so a real problem is never masked by an UNKNOWN.
func rank(s Status) int {
	switch s {
	case OK:
		return 0
	case Unknown:
		return 1
	case Warning:
		return 2
	case Critical:
		return 3
	}
	return 1
}

// Worst returns the more severe of two statuses.
func Worst(a, b Status) Status {
	if rank(b) > rank(a) {
		return b
	}
	return a
}

// Result accumulates check outcomes, detail lines and perfdata.
type Result struct {
	Summary string

	status   Status
	problems []string
	info     []string
	perf     []Perfdata
}

// Add merges a status into the result. For non-OK statuses the message is
// recorded as a long-output problem line.
func (r *Result) Add(s Status, msg string) {
	r.status = Worst(r.status, s)
	if s != OK && msg != "" {
		r.problems = append(r.problems, fmt.Sprintf("%s: %s", s, msg))
	}
}

// AddInfo records an informational long-output line, printed after any
// problem lines.
func (r *Result) AddInfo(msg string) {
	r.info = append(r.info, msg)
}

// AddPerf appends a performance data sample.
func (r *Result) AddPerf(p Perfdata) {
	r.perf = append(r.perf, p)
}

// Status returns the aggregated status.
func (r *Result) Status() Status {
	return r.status
}

// Render formats the plugin output: first line
// "SERVICE STATUS - summary | perfdata", followed by detail lines.
func (r *Result) Render(service string) string {
	var b strings.Builder
	b.WriteString(service)
	b.WriteByte(' ')
	b.WriteString(r.status.String())
	if r.Summary != "" {
		b.WriteString(" - ")
		b.WriteString(r.Summary)
	}
	if len(r.perf) > 0 {
		b.WriteString(" | ")
		for i, p := range r.perf {
			if i > 0 {
				b.WriteByte(' ')
			}
			b.WriteString(p.String())
		}
	}
	for _, d := range r.problems {
		b.WriteByte('\n')
		b.WriteString(d)
	}
	for _, d := range r.info {
		b.WriteByte('\n')
		b.WriteString(d)
	}
	return b.String()
}
