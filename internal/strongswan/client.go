package strongswan

import (
	"context"
	"fmt"

	"github.com/strongswan/govici/vici"
)

// Client is the subset of vici operations the check uses. It exists so the
// evaluation logic can be tested without a live charon daemon.
type Client interface {
	// ListConns returns loaded connections keyed by connection name.
	ListConns(ctx context.Context) (map[string]Conn, error)
	// ListSAs returns active IKE_SAs keyed by connection name. The value is
	// a slice because the same connection appears in multiple events while
	// rekeying (old and new IKE_SA overlap).
	ListSAs(ctx context.Context) (map[string][]IkeSA, error)
	// Stats returns daemon-wide counters from the stats command.
	Stats(ctx context.Context) (*Stats, error)
}

// ViciClient talks to a charon vici socket.
type ViciClient struct {
	session *vici.Session
}

// NewViciClient connects to the vici socket at path.
func NewViciClient(path string) (*ViciClient, error) {
	s, err := vici.NewSession(vici.WithSocketPath(path))
	if err != nil {
		return nil, fmt.Errorf("connecting to vici socket %s: %w", path, err)
	}
	return &ViciClient{session: s}, nil
}

// Close closes the vici session.
func (c *ViciClient) Close() error {
	return c.session.Close()
}

func (c *ViciClient) ListConns(ctx context.Context) (map[string]Conn, error) {
	conns := make(map[string]Conn)
	for m, err := range c.session.CallStreaming(ctx, "list-conns", "list-conn", nil) {
		if err != nil {
			return nil, fmt.Errorf("list-conns: %w", err)
		}
		if err := parseConnsMessage(m, conns); err != nil {
			return nil, err
		}
	}
	return conns, nil
}

func (c *ViciClient) ListSAs(ctx context.Context) (map[string][]IkeSA, error) {
	sas := make(map[string][]IkeSA)
	for m, err := range c.session.CallStreaming(ctx, "list-sas", "list-sa", nil) {
		if err != nil {
			return nil, fmt.Errorf("list-sas: %w", err)
		}
		if err := parseSAsMessage(m, sas); err != nil {
			return nil, err
		}
	}
	return sas, nil
}

func (c *ViciClient) Stats(ctx context.Context) (*Stats, error) {
	m, err := c.session.Call(ctx, "stats", nil)
	if err != nil {
		return nil, fmt.Errorf("stats: %w", err)
	}
	if err := m.Err(); err != nil {
		return nil, fmt.Errorf("stats: %w", err)
	}
	var stats Stats
	if err := vici.UnmarshalMessage(m, &stats); err != nil {
		return nil, fmt.Errorf("parsing stats reply: %w", err)
	}
	return &stats, nil
}

// parseConnsMessage merges one list-conn event message into conns.
func parseConnsMessage(m *vici.Message, conns map[string]Conn) error {
	if err := m.Err(); err != nil {
		return fmt.Errorf("list-conns: %w", err)
	}
	for _, name := range m.Keys() {
		sec, ok := m.Get(name).(*vici.Message)
		if !ok {
			continue
		}
		var conn Conn
		if err := vici.UnmarshalMessage(sec, &conn); err != nil {
			return fmt.Errorf("parsing connection %q: %w", name, err)
		}
		conns[name] = conn
	}
	return nil
}

// parseSAsMessage merges one list-sa event message into sas.
func parseSAsMessage(m *vici.Message, sas map[string][]IkeSA) error {
	if err := m.Err(); err != nil {
		return fmt.Errorf("list-sas: %w", err)
	}
	for _, name := range m.Keys() {
		sec, ok := m.Get(name).(*vici.Message)
		if !ok {
			continue
		}
		var sa IkeSA
		if err := vici.UnmarshalMessage(sec, &sa); err != nil {
			return fmt.Errorf("parsing IKE_SA %q: %w", name, err)
		}
		sas[name] = append(sas[name], sa)
	}
	return nil
}
