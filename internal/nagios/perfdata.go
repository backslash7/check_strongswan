package nagios

import (
	"strconv"
	"strings"
)

// Perfdata is one performance data sample, rendered as
// 'label'=value[UOM];[warn];[crit];[min];[max] per the guidelines.
type Perfdata struct {
	Label string
	Value float64
	UOM   string // "", "s", "%", "B", "c", ...
	Warn  *Range
	Crit  *Range
	Min   *float64
	Max   *float64
}

// SanitizeLabel makes s safe for use as a perfdata label by stripping
// characters forbidden by the guidelines (single quotes and equals signs).
func SanitizeLabel(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\'' || r == '=' {
			return -1
		}
		return r
	}, s)
}

func formatValue(v float64) string {
	return strconv.FormatFloat(v, 'f', -1, 64)
}

func (p Perfdata) String() string {
	var b strings.Builder
	b.WriteByte('\'')
	b.WriteString(SanitizeLabel(p.Label))
	b.WriteString("'=")
	b.WriteString(formatValue(p.Value))
	b.WriteString(p.UOM)

	fields := make([]string, 4)
	fields[0] = p.Warn.String()
	fields[1] = p.Crit.String()
	if p.Min != nil {
		fields[2] = formatValue(*p.Min)
	}
	if p.Max != nil {
		fields[3] = formatValue(*p.Max)
	}
	last := -1
	for i, f := range fields {
		if f != "" {
			last = i
		}
	}
	for i := 0; i <= last; i++ {
		b.WriteByte(';')
		b.WriteString(fields[i])
	}
	return b.String()
}

// Float64 returns a pointer to v, for Perfdata Min/Max fields.
func Float64(v float64) *float64 {
	return &v
}
