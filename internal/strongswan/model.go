// Package strongswan provides a typed client for the strongSwan vici
// control interface, covering the subset of commands the check needs.
package strongswan

import "strconv"

// Note on field names: list-conns responses use underscores
// (rekey_time, children), while list-sas responses use dashes
// (rekey-time, child-sas, bytes-in). All values arrive as strings.

// Conn is a loaded connection from list-conns.
type Conn struct {
	Version  string               `vici:"version"`
	Children map[string]ChildConf `vici:"children"`
}

// ChildConf is a configured CHILD_SA from list-conns.
type ChildConf struct {
	Mode      string `vici:"mode"`
	RekeyTime string `vici:"rekey_time"`
}

// IkeSA is an active IKE_SA from list-sas.
type IkeSA struct {
	UniqueID    string             `vici:"uniqueid"`
	Version     string             `vici:"version"`
	State       string             `vici:"state"` // ESTABLISHED, CONNECTING, REKEYING, ...
	Established string             `vici:"established"`
	RekeyTime   string             `vici:"rekey-time"`  // absent if rekeying disabled
	ReauthTime  string             `vici:"reauth-time"` // absent if reauth disabled
	ChildSAs    map[string]ChildSA `vici:"child-sas"`   // keyed "<name>-<uniqueid>"
}

// ChildSA is an active CHILD_SA from list-sas.
type ChildSA struct {
	Name        string `vici:"name"`
	State       string `vici:"state"` // INSTALLED, REKEYING, REKEYED, ROUTED, ...
	BytesIn     string `vici:"bytes-in"`
	BytesOut    string `vici:"bytes-out"`
	PacketsIn   string `vici:"packets-in"`
	PacketsOut  string `vici:"packets-out"`
	RekeyTime   string `vici:"rekey-time"` // absent if rekeying disabled
	LifeTime    string `vici:"life-time"`
	InstallTime string `vici:"install-time"`
}

// Stats is the subset of a get-stats reply the check uses.
type Stats struct {
	IkeSAs StatsIkeSAs `vici:"ikesas"`
}

// StatsIkeSAs holds daemon-wide IKE_SA counters.
type StatsIkeSAs struct {
	Total    string `vici:"total"`
	HalfOpen string `vici:"half-open"`
}

// Seconds parses a vici numeric string field. It returns ok=false for
// absent (empty) fields, so callers can distinguish "disabled" from 0.
func Seconds(s string) (v int64, ok bool) {
	if s == "" {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}
