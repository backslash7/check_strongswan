// Package check evaluates strongSwan state into a Nagios result.
package check

import (
	"fmt"
	"maps"
	"slices"

	"github.com/backslash7/check_strongswan/internal/nagios"
	"github.com/backslash7/check_strongswan/internal/strongswan"
)

// Options selects which connections are checked and which thresholds apply.
// All lifetime thresholds are Nagios ranges over "seconds remaining"; nil
// means the threshold is not checked (perfdata is still emitted).
type Options struct {
	// Conns restricts the check to these connection names; empty means all.
	Conns []string
	// Ignore excludes connection names from the check.
	Ignore []string

	IkeRekeyWarn, IkeRekeyCrit     *nagios.Range
	IkeReauthWarn, IkeReauthCrit   *nagios.Range
	ChildRekeyWarn, ChildRekeyCrit *nagios.Range
	ChildLifeWarn, ChildLifeCrit   *nagios.Range

	// ChildrenSeverity is raised when fewer CHILD_SAs are installed than
	// configured for an up connection. Zero value (OK) disables the check.
	ChildrenSeverity nagios.Status
}

// Evaluate turns loaded connections, active SAs and daemon stats into a
// Nagios result. A connection counts as up when at least one of its IKE_SAs
// is ESTABLISHED. stats may be nil.
func Evaluate(conns map[string]strongswan.Conn, sas map[string][]strongswan.IkeSA, stats *strongswan.Stats, opts Options) *nagios.Result {
	res := &nagios.Result{}

	names := selectConns(conns, opts, res)

	up := 0
	for _, name := range names {
		sa, established := establishedSA(sas[name])
		if !established {
			res.Add(nagios.Critical, fmt.Sprintf("connection %q is down (%s)", name, downReason(sas[name])))
			continue
		}
		up++
		checkIkeSA(res, name, sa, opts)
		checkChildren(res, name, conns[name], sas[name], opts)

		uptime, _ := strongswan.Seconds(sa.Established)
		res.AddInfo(fmt.Sprintf("%s: ESTABLISHED (IKEv%s), up %ds", name, sa.Version, uptime))
	}

	total := float64(len(names))
	res.AddPerf(nagios.Perfdata{Label: "conns_up", Value: float64(up), Min: nagios.Float64(0), Max: &total})
	res.AddPerf(nagios.Perfdata{Label: "conns_down", Value: total - float64(up), Min: nagios.Float64(0), Max: &total})
	if stats != nil {
		if v, ok := strongswan.Seconds(stats.IkeSAs.Total); ok {
			res.AddPerf(nagios.Perfdata{Label: "ike_sas", Value: float64(v), Min: nagios.Float64(0)})
		}
		if v, ok := strongswan.Seconds(stats.IkeSAs.HalfOpen); ok {
			res.AddPerf(nagios.Perfdata{Label: "half_open_ike_sas", Value: float64(v), Min: nagios.Float64(0)})
		}
	}
	res.Summary = fmt.Sprintf("%d/%d connections up", up, len(names))
	return res
}

// checkIkeSA checks phase 1 (IKE_SA) lifetimes of the newest established SA.
// An absent rekey-time/reauth-time field means that mechanism is disabled,
// so the corresponding check is skipped entirely.
func checkIkeSA(res *nagios.Result, name string, sa strongswan.IkeSA, opts Options) {
	if uptime, ok := strongswan.Seconds(sa.Established); ok {
		res.AddPerf(nagios.Perfdata{
			Label: name + "_established", Value: float64(uptime), UOM: "s", Min: nagios.Float64(0),
		})
	}
	if v, ok := strongswan.Seconds(sa.RekeyTime); ok {
		st := lifetimeStatus(float64(v), opts.IkeRekeyWarn, opts.IkeRekeyCrit)
		res.Add(st, fmt.Sprintf("connection %q IKE_SA rekeys in %ds", name, v))
		res.AddPerf(nagios.Perfdata{
			Label: name + "_ike_rekey", Value: float64(v), UOM: "s",
			Warn: opts.IkeRekeyWarn, Crit: opts.IkeRekeyCrit, Min: nagios.Float64(0),
		})
	}
	if v, ok := strongswan.Seconds(sa.ReauthTime); ok {
		st := lifetimeStatus(float64(v), opts.IkeReauthWarn, opts.IkeReauthCrit)
		res.Add(st, fmt.Sprintf("connection %q IKE_SA reauthenticates in %ds", name, v))
		res.AddPerf(nagios.Perfdata{
			Label: name + "_ike_reauth", Value: float64(v), UOM: "s",
			Warn: opts.IkeReauthWarn, Crit: opts.IkeReauthCrit, Min: nagios.Float64(0),
		})
	}
}

// childAgg aggregates CHILD_SA state across all of a connection's IKE_SAs;
// during a rekey the same child name exists twice (old and new SA), so
// lifetimes take the maximum remaining and traffic counters are summed.
type childAgg struct {
	installed             bool
	rekey, life           int64
	hasRekey, hasLife     bool
	bytesIn, bytesOut     int64
	packetsIn, packetsOut int64
}

// checkChildren checks phase 2 (CHILD_SA) installation count, lifetimes and
// traffic counters for an up connection.
func checkChildren(res *nagios.Result, name string, conn strongswan.Conn, sas []strongswan.IkeSA, opts Options) {
	aggs := make(map[string]*childAgg)
	for _, sa := range sas {
		if sa.State != "ESTABLISHED" {
			continue
		}
		for _, cs := range sa.ChildSAs {
			agg := aggs[cs.Name]
			if agg == nil {
				agg = &childAgg{}
				aggs[cs.Name] = agg
			}
			if cs.State == "INSTALLED" {
				agg.installed = true
			}
			if v, ok := strongswan.Seconds(cs.RekeyTime); ok && (!agg.hasRekey || v > agg.rekey) {
				agg.rekey, agg.hasRekey = v, true
			}
			if v, ok := strongswan.Seconds(cs.LifeTime); ok && (!agg.hasLife || v > agg.life) {
				agg.life, agg.hasLife = v, true
			}
			addCounter(&agg.bytesIn, cs.BytesIn)
			addCounter(&agg.bytesOut, cs.BytesOut)
			addCounter(&agg.packetsIn, cs.PacketsIn)
			addCounter(&agg.packetsOut, cs.PacketsOut)
		}
	}

	installed := 0
	for _, agg := range aggs {
		if agg.installed {
			installed++
		}
	}
	expected := len(conn.Children)
	if expected > 0 {
		if installed < expected && opts.ChildrenSeverity != nagios.OK {
			res.Add(opts.ChildrenSeverity,
				fmt.Sprintf("connection %q has %d of %d CHILD_SAs installed", name, installed, expected))
		}
		max := float64(expected)
		res.AddPerf(nagios.Perfdata{
			Label: name + "_children", Value: float64(installed), Min: nagios.Float64(0), Max: &max,
		})
	}

	for _, child := range slices.Sorted(maps.Keys(aggs)) {
		agg := aggs[child]
		prefix := name + "_" + child
		if agg.hasRekey {
			st := lifetimeStatus(float64(agg.rekey), opts.ChildRekeyWarn, opts.ChildRekeyCrit)
			res.Add(st, fmt.Sprintf("connection %q CHILD_SA %q rekeys in %ds", name, child, agg.rekey))
			res.AddPerf(nagios.Perfdata{
				Label: prefix + "_rekey", Value: float64(agg.rekey), UOM: "s",
				Warn: opts.ChildRekeyWarn, Crit: opts.ChildRekeyCrit, Min: nagios.Float64(0),
			})
		}
		if agg.hasLife {
			st := lifetimeStatus(float64(agg.life), opts.ChildLifeWarn, opts.ChildLifeCrit)
			res.Add(st, fmt.Sprintf("connection %q CHILD_SA %q expires in %ds", name, child, agg.life))
			res.AddPerf(nagios.Perfdata{
				Label: prefix + "_life", Value: float64(agg.life), UOM: "s",
				Warn: opts.ChildLifeWarn, Crit: opts.ChildLifeCrit, Min: nagios.Float64(0),
			})
		}
		// Not UOM "c": per-SA counters reset when the CHILD_SA rekeys,
		// so these values are not monotonic.
		res.AddPerf(nagios.Perfdata{Label: prefix + "_bytes_in", Value: float64(agg.bytesIn), UOM: "B", Min: nagios.Float64(0)})
		res.AddPerf(nagios.Perfdata{Label: prefix + "_bytes_out", Value: float64(agg.bytesOut), UOM: "B", Min: nagios.Float64(0)})
		res.AddPerf(nagios.Perfdata{Label: prefix + "_packets_in", Value: float64(agg.packetsIn), Min: nagios.Float64(0)})
		res.AddPerf(nagios.Perfdata{Label: prefix + "_packets_out", Value: float64(agg.packetsOut), Min: nagios.Float64(0)})
	}
}

func addCounter(dst *int64, s string) {
	if v, ok := strongswan.Seconds(s); ok {
		*dst += v
	}
}

// lifetimeStatus applies warn/crit ranges to a seconds-remaining value;
// crit wins over warn.
func lifetimeStatus(v float64, warn, crit *nagios.Range) nagios.Status {
	if crit != nil && crit.Violated(v) {
		return nagios.Critical
	}
	if warn != nil && warn.Violated(v) {
		return nagios.Warning
	}
	return nagios.OK
}

// selectConns applies include/ignore filters and returns sorted connection
// names. Explicitly requested connections that are not loaded are reported
// as UNKNOWN (configuration error).
func selectConns(conns map[string]strongswan.Conn, opts Options, res *nagios.Result) []string {
	var names []string
	if len(opts.Conns) > 0 {
		for _, name := range opts.Conns {
			if _, ok := conns[name]; !ok {
				res.Add(nagios.Unknown, fmt.Sprintf("connection %q is not loaded", name))
				continue
			}
			names = append(names, name)
		}
	} else {
		for name := range conns {
			names = append(names, name)
		}
	}
	names = slices.DeleteFunc(names, func(name string) bool {
		return slices.Contains(opts.Ignore, name)
	})
	slices.Sort(names)
	return slices.Compact(names)
}

// establishedSA returns the newest ESTABLISHED IKE_SA (smallest established
// age), so mid-rekey the fresh SA is the one reported.
func establishedSA(sas []strongswan.IkeSA) (strongswan.IkeSA, bool) {
	var best strongswan.IkeSA
	found := false
	var bestAge int64
	for _, sa := range sas {
		if sa.State != "ESTABLISHED" {
			continue
		}
		age, ok := strongswan.Seconds(sa.Established)
		if !ok {
			age = 0
		}
		if !found || age < bestAge {
			best, bestAge, found = sa, age, true
		}
	}
	return best, found
}

func downReason(sas []strongswan.IkeSA) string {
	if len(sas) == 0 {
		return "no IKE_SA"
	}
	reason := "state: " + sas[0].State
	if len(sas) > 1 {
		reason += fmt.Sprintf(" (+%d more)", len(sas)-1)
	}
	return reason
}
