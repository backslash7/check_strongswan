//go:build integration

package strongswan

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestLiveSocket exercises the client against a running charon. It needs
// read access to the vici socket (typically root); run via `sudo make integration`.
// Override the socket path with CHECK_STRONGSWAN_SOCKET.
func TestLiveSocket(t *testing.T) {
	sock := os.Getenv("CHECK_STRONGSWAN_SOCKET")
	if sock == "" {
		sock = "/var/run/charon.vici"
	}
	if _, err := os.Stat(sock); err != nil {
		t.Skipf("vici socket %s not available: %v", sock, err)
	}

	client, err := NewViciClient(sock)
	if err != nil {
		t.Fatalf("NewViciClient: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conns, err := client.ListConns(ctx)
	if err != nil {
		t.Fatalf("ListConns: %v", err)
	}
	sas, err := client.ListSAs(ctx)
	if err != nil {
		t.Fatalf("ListSAs: %v", err)
	}
	t.Logf("loaded conns: %d, conns with active IKE_SAs: %d", len(conns), len(sas))

	// Every active SA should belong to some loaded conn.
	for name := range sas {
		if _, ok := conns[name]; !ok {
			t.Errorf("IKE_SA %q has no loaded connection", name)
		}
	}
}
