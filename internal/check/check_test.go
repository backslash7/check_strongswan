package check

import (
	"strings"
	"testing"

	"github.com/backslash7/check_strongswan/internal/nagios"
	"github.com/backslash7/check_strongswan/internal/strongswan"
)

func conn(children ...string) strongswan.Conn {
	c := strongswan.Conn{Version: "IKEv2", Children: map[string]strongswan.ChildConf{}}
	for _, name := range children {
		c.Children[name] = strongswan.ChildConf{Mode: "TUNNEL"}
	}
	return c
}

func established(age string) strongswan.IkeSA {
	return strongswan.IkeSA{State: "ESTABLISHED", Established: age, Version: "2"}
}

func mustLifetime(t *testing.T, s string) *nagios.Range {
	t.Helper()
	r, err := nagios.ParseLifetime(s)
	if err != nil {
		t.Fatalf("ParseLifetime(%q): %v", s, err)
	}
	return r
}

func TestEvaluate(t *testing.T) {
	warn600 := func(t *testing.T) *nagios.Range { return mustLifetime(t, "600") }
	crit300 := func(t *testing.T) *nagios.Range { return mustLifetime(t, "300") }

	cases := []struct {
		name       string
		conns      map[string]strongswan.Conn
		sas        map[string][]strongswan.IkeSA
		stats      *strongswan.Stats
		opts       func(t *testing.T) Options
		wantStatus nagios.Status
		wantOutput []string // substrings of rendered output
	}{
		{
			name:       "all up",
			conns:      map[string]strongswan.Conn{"a": conn(), "b": conn()},
			sas:        map[string][]strongswan.IkeSA{"a": {established("10")}, "b": {established("20")}},
			wantStatus: nagios.OK,
			wantOutput: []string{"2/2 connections up", "'conns_up'=2;;;0;2", "'conns_down'=0;;;0;2", "'a_established'=10s", "a: ESTABLISHED (IKEv2), up 10s"},
		},
		{
			name:       "one down no SA",
			conns:      map[string]strongswan.Conn{"a": conn(), "b": conn()},
			sas:        map[string][]strongswan.IkeSA{"a": {established("10")}},
			wantStatus: nagios.Critical,
			wantOutput: []string{"1/2 connections up", `connection "b" is down (no IKE_SA)`},
		},
		{
			name:       "connecting is down",
			conns:      map[string]strongswan.Conn{"a": conn()},
			sas:        map[string][]strongswan.IkeSA{"a": {{State: "CONNECTING"}}},
			wantStatus: nagios.Critical,
			wantOutput: []string{`connection "a" is down (state: CONNECTING)`},
		},
		{
			name:  "mid-rekey newest SA reported",
			conns: map[string]strongswan.Conn{"a": conn()},
			sas: map[string][]strongswan.IkeSA{
				"a": {{State: "REKEYED", Established: "7200"}, established("5")},
			},
			wantStatus: nagios.OK,
			wantOutput: []string{"'a_established'=5s"},
		},
		{
			name:       "conn filter",
			conns:      map[string]strongswan.Conn{"a": conn(), "b": conn()},
			sas:        map[string][]strongswan.IkeSA{"a": {established("10")}},
			opts:       func(*testing.T) Options { return Options{Conns: []string{"a"}} },
			wantStatus: nagios.OK,
			wantOutput: []string{"1/1 connections up"},
		},
		{
			name:       "unknown conn requested",
			conns:      map[string]strongswan.Conn{"a": conn()},
			sas:        map[string][]strongswan.IkeSA{"a": {established("10")}},
			opts:       func(*testing.T) Options { return Options{Conns: []string{"a", "nope"}} },
			wantStatus: nagios.Unknown,
			wantOutput: []string{`connection "nope" is not loaded`},
		},
		{
			name:       "ignore filter",
			conns:      map[string]strongswan.Conn{"a": conn(), "b": conn()},
			sas:        map[string][]strongswan.IkeSA{"a": {established("10")}},
			opts:       func(*testing.T) Options { return Options{Ignore: []string{"b"}} },
			wantStatus: nagios.OK,
			wantOutput: []string{"1/1 connections up"},
		},
		{
			name:       "down beats unknown",
			conns:      map[string]strongswan.Conn{"a": conn()},
			sas:        map[string][]strongswan.IkeSA{},
			opts:       func(*testing.T) Options { return Options{Conns: []string{"a", "nope"}} },
			wantStatus: nagios.Critical,
			wantOutput: []string{`connection "a" is down`, `connection "nope" is not loaded`},
		},
		{
			name:       "no conns loaded",
			conns:      map[string]strongswan.Conn{},
			sas:        map[string][]strongswan.IkeSA{},
			wantStatus: nagios.OK,
			wantOutput: []string{"0/0 connections up"},
		},
		{
			name:  "ike rekey below warn",
			conns: map[string]strongswan.Conn{"a": conn()},
			sas: map[string][]strongswan.IkeSA{
				"a": {{State: "ESTABLISHED", Established: "100", Version: "2", RekeyTime: "500"}},
			},
			opts: func(t *testing.T) Options {
				return Options{IkeRekeyWarn: warn600(t), IkeRekeyCrit: crit300(t)}
			},
			wantStatus: nagios.Warning,
			wantOutput: []string{`connection "a" IKE_SA rekeys in 500s`, "'a_ike_rekey'=500s;600:;300:;0"},
		},
		{
			name:  "ike rekey below crit",
			conns: map[string]strongswan.Conn{"a": conn()},
			sas: map[string][]strongswan.IkeSA{
				"a": {{State: "ESTABLISHED", Established: "100", Version: "2", RekeyTime: "200"}},
			},
			opts: func(t *testing.T) Options {
				return Options{IkeRekeyWarn: warn600(t), IkeRekeyCrit: crit300(t)}
			},
			wantStatus: nagios.Critical,
		},
		{
			name:  "rekey disabled skips threshold",
			conns: map[string]strongswan.Conn{"a": conn()},
			sas: map[string][]strongswan.IkeSA{
				"a": {{State: "ESTABLISHED", Established: "100", Version: "2"}}, // no rekey-time
			},
			opts: func(t *testing.T) Options {
				return Options{IkeRekeyWarn: warn600(t), IkeRekeyCrit: crit300(t)}
			},
			wantStatus: nagios.OK,
		},
		{
			name:  "missing child critical",
			conns: map[string]strongswan.Conn{"a": conn("net", "dmz")},
			sas: map[string][]strongswan.IkeSA{
				"a": {{State: "ESTABLISHED", Established: "100", Version: "2",
					ChildSAs: map[string]strongswan.ChildSA{
						"net-1": {Name: "net", State: "INSTALLED"},
					}}},
			},
			opts:       func(*testing.T) Options { return Options{ChildrenSeverity: nagios.Critical} },
			wantStatus: nagios.Critical,
			wantOutput: []string{`connection "a" has 1 of 2 CHILD_SAs installed`, "'a_children'=1;;;0;2"},
		},
		{
			name:  "missing child severity ok disables",
			conns: map[string]strongswan.Conn{"a": conn("net", "dmz")},
			sas: map[string][]strongswan.IkeSA{
				"a": {{State: "ESTABLISHED", Established: "100", Version: "2",
					ChildSAs: map[string]strongswan.ChildSA{
						"net-1": {Name: "net", State: "INSTALLED"},
					}}},
			},
			wantStatus: nagios.OK,
		},
		{
			name:  "child lifetime and traffic aggregation over rekey pair",
			conns: map[string]strongswan.Conn{"a": conn("net")},
			sas: map[string][]strongswan.IkeSA{
				"a": {{State: "ESTABLISHED", Established: "100", Version: "2",
					ChildSAs: map[string]strongswan.ChildSA{
						"net-1": {Name: "net", State: "REKEYED", RekeyTime: "10", LifeTime: "60",
							BytesIn: "100", BytesOut: "200", PacketsIn: "3", PacketsOut: "4"},
						"net-2": {Name: "net", State: "INSTALLED", RekeyTime: "3000", LifeTime: "3600",
							BytesIn: "1000", BytesOut: "2000", PacketsIn: "30", PacketsOut: "40"},
					}}},
			},
			opts: func(t *testing.T) Options {
				return Options{ChildRekeyWarn: warn600(t), ChildrenSeverity: nagios.Critical}
			},
			wantStatus: nagios.OK, // max remaining (3000) is above warn
			wantOutput: []string{
				"'a_net_rekey'=3000s;600:;;0",
				"'a_net_life'=3600s;;;0",
				"'a_net_bytes_in'=1100B",
				"'a_net_bytes_out'=2200B",
				"'a_net_packets_in'=33;",
				"'a_net_packets_out'=44;",
			},
		},
		{
			name:  "stats perfdata",
			conns: map[string]strongswan.Conn{},
			sas:   map[string][]strongswan.IkeSA{},
			stats: &strongswan.Stats{IkeSAs: strongswan.StatsIkeSAs{Total: "5", HalfOpen: "1"}},
			wantOutput: []string{
				"'ike_sas'=5;;;0",
				"'half_open_ike_sas'=1;;;0",
			},
			wantStatus: nagios.OK,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			opts := Options{}
			if c.opts != nil {
				opts = c.opts(t)
			}
			res := Evaluate(c.conns, c.sas, c.stats, opts)
			if res.Status() != c.wantStatus {
				t.Errorf("status = %s, want %s", res.Status(), c.wantStatus)
			}
			out := res.Render("STRONGSWAN")
			for _, want := range c.wantOutput {
				if !strings.Contains(out, want) {
					t.Errorf("output missing %q:\n%s", want, out)
				}
			}
		})
	}
}
