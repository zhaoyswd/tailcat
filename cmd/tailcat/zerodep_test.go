package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/tstest/integration"
)

// TestZeroDerpDirectConnect is the acceptance test for "a reachable exit needs
// no DERP": the client is given a DERP map whose only region points at a closed
// port, and a manual endpoint hint pointing at the exit's real address, which is
// all a phone with an unreachable/blocked DERP would have.
//
// Before the magicsock direct-bootstrap patch this fails: the client's handshake
// is relayed (addrForSendLocked returns only derpAddr for a peer without a
// verified bestAddr), and even if it went direct the exit could not admit it
// (wgcfg.NewPeerLookupFunc → magicsock.ParseEndpoint rejects unknown node keys)
// nor reply (no known address for the sender), so the tunnel never comes up and
// the readiness basis stays "meow" until it times out.
//
// With the patch: the handshake goes to the hint, the exit synthesizes a
// provisional endpoint from the observed source address, and readiness is
// "direct". We also assert the exit never processed a meow, i.e. no DERP
// rendezvous happened at all.
func TestZeroDerpDirectConnect(t *testing.T) {
	t.Parallel()
	e := newZeroDerpEnv(t)
	port := startEchoListener(t)
	dst := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)

	listen := freePort(t)
	_, addr, serverStderr := e.startServer("--verbose", "--serve=exit-node",
		"--listen-port="+strconv.Itoa(listen),
		"--endpoint=127.0.0.1:"+strconv.Itoa(listen))

	const payload = "echo without any derp"
	client := e.cmd("--verbose", "--key=new", "--derpmap-url="+e.deadDerpMapURL,
		"--direct-connect", addr, dst.String())
	// runClient (serve_test.go) owns the client's stderr, so drive the process
	// here to keep the client's log for the readiness assertion below.
	got, clientLog, err := runZeroDerpClient(t, client, serverStderr, payload)
	if err != nil {
		t.Fatalf("direct-only client: %v", err)
	}
	if got != payload {
		t.Errorf("echoed %q; want %q", got, payload)
	}
	// "ready by direct" is the CLI's wording; the app core logs
	// "就绪（判据=direct）". Accept either.
	if !strings.Contains(clientLog, "direct") || !(strings.Contains(clientLog, "ready by direct") ||
		strings.Contains(clientLog, "判据=direct")) {
		t.Errorf("readiness was not direct; client log:\n%s", clientLog)
	}
	if strings.Contains(serverStderr.String(), "got meow") {
		t.Errorf("exit processed a meow: this run was not DERP-free\n%s", serverStderr.String())
	}
}

// runZeroDerpClient is runClient (serve_test.go) with the client's stderr kept
// as a string so the caller can assert on its log lines.
func runZeroDerpClient(t *testing.T, client *exec.Cmd, serverStderr *lockedBuf, payload string) (stdout, stderr string, err error) {
	t.Helper()
	client.Stdin = strings.NewReader(payload)
	var outBuf, errBuf bytes.Buffer
	client.Stdout = &outBuf
	client.Stderr = &errBuf
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- client.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			err = fmt.Errorf("%w\nclient stderr:\n%s\nserver stderr:\n%s",
				err, errBuf.String(), serverStderr.String())
		}
		return outBuf.String(), errBuf.String(), err
	case <-time.After(60 * time.Second):
		client.Process.Kill()
		t.Fatalf("client did not exit within 60s\nclient stderr:\n%s\nserver stderr:\n%s",
			errBuf.String(), serverStderr.String())
		panic("unreachable")
	}
}

// zeroDerpEnv is newTestEnv plus a DERP map whose regions are unreachable, for
// the client only. The exit keeps the working local DERP so that anything that
// is not the direct path is a test failure rather than a broken environment.
type zeroDerpEnv struct {
	*testEnv
	deadDerpMapURL string
}

func newZeroDerpEnv(t *testing.T) *zeroDerpEnv {
	t.Helper()
	e := newTestEnv(t)

	dm := integration.RunDERPAndSTUN(t, t.Logf, "127.0.0.1")
	dead := &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{}}
	for id, r := range dm.Regions {
		dead.Regions[id] = &tailcfg.DERPRegion{
			RegionID:   r.RegionID,
			RegionCode: r.RegionCode,
			RegionName: r.RegionName,
			Nodes: []*tailcfg.DERPNode{{
				Name:     fmt.Sprintf("dead-%d", id),
				RegionID: r.RegionID,
				// Closed port: every DERP/STUN attempt from the client fails.
				HostName: "127.0.0.1",
				IPv4:     "127.0.0.1",
				DERPPort: 1,
				STUNPort: 1,
			}},
		}
	}
	raw, err := json.Marshal(dead)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(raw)
	}))
	t.Cleanup(srv.Close)
	return &zeroDerpEnv{testEnv: e, deadDerpMapURL: srv.URL}
}
