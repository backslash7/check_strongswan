package strongswan

import (
	"testing"

	"github.com/strongswan/govici/vici"
)

// buildMessage builds a vici.Message from nested key/values, mirroring the
// shape of real list-conn / list-sa event messages.
func buildMessage(t *testing.T, kv map[string]any) *vici.Message {
	t.Helper()
	m := vici.NewMessage()
	for k, v := range kv {
		var err error
		switch val := v.(type) {
		case string:
			err = m.Set(k, val)
		case map[string]any:
			err = m.Set(k, buildMessage(t, val))
		default:
			t.Fatalf("unsupported fixture value type %T", v)
		}
		if err != nil {
			t.Fatalf("Set(%q): %v", k, err)
		}
	}
	return m
}

func TestParseConnsMessage(t *testing.T) {
	// Shape of a list-conn event: conn names as top-level keys,
	// list-conns fields use underscores.
	m := buildMessage(t, map[string]any{
		"office": map[string]any{
			"version":     "IKEv2",
			"rekey_time":  "14400",
			"reauth_time": "0",
			"children": map[string]any{
				"office-net": map[string]any{"mode": "TUNNEL", "rekey_time": "3600"},
				"office-dmz": map[string]any{"mode": "TUNNEL", "rekey_time": "3600"},
			},
		},
	})

	conns := make(map[string]Conn)
	if err := parseConnsMessage(m, conns); err != nil {
		t.Fatalf("parseConnsMessage: %v", err)
	}
	conn, ok := conns["office"]
	if !ok {
		t.Fatalf("connection office missing, got %v", conns)
	}
	if conn.Version != "IKEv2" {
		t.Errorf("Version = %q, want IKEv2", conn.Version)
	}
	if len(conn.Children) != 2 {
		t.Errorf("len(Children) = %d, want 2", len(conn.Children))
	}
	if conn.Children["office-net"].Mode != "TUNNEL" {
		t.Errorf("child mode = %q, want TUNNEL", conn.Children["office-net"].Mode)
	}
}

func TestParseSAsMessage(t *testing.T) {
	// Shape of a list-sa event: conn names as top-level keys, list-sas
	// fields use dashes, child-sas keyed "<name>-<uniqueid>".
	m := buildMessage(t, map[string]any{
		"office": map[string]any{
			"uniqueid":    "7",
			"version":     "2",
			"state":       "ESTABLISHED",
			"established": "1234",
			"rekey-time":  "9000",
			"child-sas": map[string]any{
				"office-net-42": map[string]any{
					"name":       "office-net",
					"state":      "INSTALLED",
					"bytes-in":   "1000",
					"bytes-out":  "2000",
					"rekey-time": "2500",
					"life-time":  "3300",
				},
			},
		},
	})

	sas := make(map[string][]IkeSA)
	if err := parseSAsMessage(m, sas); err != nil {
		t.Fatalf("parseSAsMessage: %v", err)
	}
	if len(sas["office"]) != 1 {
		t.Fatalf("len(sas[office]) = %d, want 1", len(sas["office"]))
	}
	sa := sas["office"][0]
	if sa.State != "ESTABLISHED" || sa.Established != "1234" || sa.RekeyTime != "9000" {
		t.Errorf("unexpected IkeSA: %+v", sa)
	}
	if sa.ReauthTime != "" {
		t.Errorf("ReauthTime = %q, want empty (absent field)", sa.ReauthTime)
	}
	child, ok := sa.ChildSAs["office-net-42"]
	if !ok {
		t.Fatalf("child office-net-42 missing: %+v", sa.ChildSAs)
	}
	if child.Name != "office-net" || child.State != "INSTALLED" || child.BytesIn != "1000" {
		t.Errorf("unexpected ChildSA: %+v", child)
	}

	// Second event for the same conn (mid-rekey) must append, not replace.
	m2 := buildMessage(t, map[string]any{
		"office": map[string]any{
			"uniqueid": "8", "version": "2", "state": "REKEYED", "established": "7200",
		},
	})
	if err := parseSAsMessage(m2, sas); err != nil {
		t.Fatalf("parseSAsMessage(second event): %v", err)
	}
	if len(sas["office"]) != 2 {
		t.Errorf("len(sas[office]) = %d after second event, want 2", len(sas["office"]))
	}
}

func TestSeconds(t *testing.T) {
	if v, ok := Seconds("42"); !ok || v != 42 {
		t.Errorf("Seconds(42) = %d, %v", v, ok)
	}
	if _, ok := Seconds(""); ok {
		t.Error("Seconds(\"\") should report absent")
	}
	if _, ok := Seconds("abc"); ok {
		t.Error("Seconds(abc) should fail")
	}
}
