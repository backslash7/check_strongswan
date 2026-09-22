package nagios

import "testing"

func TestWorst(t *testing.T) {
	cases := []struct {
		a, b, want Status
	}{
		{OK, OK, OK},
		{OK, Unknown, Unknown},
		{Unknown, Warning, Warning},
		{Warning, Critical, Critical},
		{Critical, Unknown, Critical}, // UNKNOWN must not mask CRITICAL
		{Warning, Unknown, Warning},
		{Critical, OK, Critical},
	}
	for _, c := range cases {
		if got := Worst(c.a, c.b); got != c.want {
			t.Errorf("Worst(%s, %s) = %s, want %s", c.a, c.b, got, c.want)
		}
	}
}

func TestParseRange(t *testing.T) {
	cases := []struct {
		spec    string
		value   float64
		violate bool
	}{
		{"10", 5, false},
		{"10", 11, true},
		{"10", -1, true},
		{"10:", 9, true},
		{"10:", 10, false},
		{"~:10", -100, false},
		{"~:10", 11, true},
		{"10:20", 15, false},
		{"10:20", 9, true},
		{"10:20", 21, true},
		{"@10:20", 15, true},
		{"@10:20", 9, false},
	}
	for _, c := range cases {
		r, err := ParseRange(c.spec)
		if err != nil {
			t.Fatalf("ParseRange(%q): %v", c.spec, err)
		}
		if got := r.Violated(c.value); got != c.violate {
			t.Errorf("ParseRange(%q).Violated(%v) = %v, want %v", c.spec, c.value, got, c.violate)
		}
		if r.String() != c.spec {
			t.Errorf("ParseRange(%q).String() = %q", c.spec, r.String())
		}
	}

	for _, bad := range []string{"", "@", "abc", "20:10", "1:2:3"} {
		if _, err := ParseRange(bad); err == nil {
			t.Errorf("ParseRange(%q): expected error", bad)
		}
	}
}

func TestParseLifetime(t *testing.T) {
	// Bare number: alert when value drops below it.
	r, err := ParseLifetime("600")
	if err != nil {
		t.Fatalf("ParseLifetime(600): %v", err)
	}
	if !r.Violated(599) || r.Violated(600) || r.Violated(10000) {
		t.Errorf("ParseLifetime(600) semantics wrong: %+v", r)
	}
	if r.String() != "600:" {
		t.Errorf("ParseLifetime(600).String() = %q, want \"600:\"", r.String())
	}

	// Range syntax passes through unchanged.
	r, err = ParseLifetime("~:100")
	if err != nil {
		t.Fatalf("ParseLifetime(~:100): %v", err)
	}
	if r.Violated(50) || !r.Violated(101) {
		t.Errorf("ParseLifetime(~:100) semantics wrong: %+v", r)
	}

	if _, err := ParseLifetime("abc"); err == nil {
		t.Error("ParseLifetime(abc): expected error")
	}
}

func TestPerfdataString(t *testing.T) {
	warn, _ := ParseRange("600:")
	crit, _ := ParseRange("300:")
	cases := []struct {
		p    Perfdata
		want string
	}{
		{Perfdata{Label: "conns_up", Value: 2}, "'conns_up'=2"},
		{Perfdata{Label: "uptime", Value: 1234, UOM: "s", Min: Float64(0)}, "'uptime'=1234s;;;0"},
		{
			Perfdata{Label: "ike_rekey", Value: 500, UOM: "s", Warn: warn, Crit: crit, Min: Float64(0)},
			"'ike_rekey'=500s;600:;300:;0",
		},
		{
			Perfdata{Label: "children", Value: 1, Min: Float64(0), Max: Float64(2)},
			"'children'=1;;;0;2",
		},
		{Perfdata{Label: "bad'la=bel", Value: 0.5}, "'badlabel'=0.5"},
	}
	for _, c := range cases {
		if got := c.p.String(); got != c.want {
			t.Errorf("Perfdata.String() = %q, want %q", got, c.want)
		}
	}
}

func TestResultRender(t *testing.T) {
	var r Result
	r.Summary = "2/3 connections up"
	r.Add(OK, "")
	r.Add(Critical, `connection "office" is down (no IKE_SA)`)
	r.AddPerf(Perfdata{Label: "conns_up", Value: 2})
	r.AddPerf(Perfdata{Label: "conns_down", Value: 1})

	want := "STRONGSWAN CRITICAL - 2/3 connections up | 'conns_up'=2 'conns_down'=1\n" +
		`CRITICAL: connection "office" is down (no IKE_SA)`
	if got := r.Render("STRONGSWAN"); got != want {
		t.Errorf("Render() = %q, want %q", got, want)
	}
	if r.Status() != Critical {
		t.Errorf("Status() = %s, want CRITICAL", r.Status())
	}
}
