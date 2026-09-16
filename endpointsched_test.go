package tailcat

import (
	"net/netip"
	"testing"
	"time"
)

func schedHint(ap string, tier int) EndpointHint {
	return EndpointHint{AddrPort: netip.MustParseAddrPort(ap), Tier: tier, Generated: time.Now().Unix()}
}

func TestFilterHintsCellularDropsPrivate(t *testing.T) {
	hints := []EndpointHint{
		schedHint("192.168.3.12:41641", EndpointHintLAN),
		schedHint("114.242.60.128:41641", EndpointHintTrusted),
		schedHint("[2606:4700::1]:41641", EndpointHintBestEffort),
		schedHint("100.64.5.5:41641", EndpointHintLAN), // CGNAT 也算私网
	}
	learned := []netip.AddrPort{netip.MustParseAddrPort("192.168.3.12:41699")}
	keep, dropped := FilterHints(learned, hints, "cellular")
	if len(dropped) != 3 || dropped[0].String() != "192.168.3.12:41699" || dropped[1].String() != "192.168.3.12:41641" || dropped[2].String() != "100.64.5.5:41641" {
		t.Fatalf("dropped = %v; want learned-LAN + hint-LAN + hint-CGNAT", dropped)
	}
	if len(keep) != 2 {
		t.Fatalf("keep = %v", keep)
	}
	for _, ap := range keep {
		if ap.Addr().IsPrivate() {
			t.Errorf("private %v survived cellular filter", ap)
		}
	}
}

func TestFilterHintsNonCellularKeepsAll(t *testing.T) {
	hints := []EndpointHint{
		schedHint("192.168.3.12:41641", EndpointHintLAN),
		schedHint("114.242.60.128:41641", EndpointHintTrusted),
	}
	for _, bearer := range []string{"wifi", "", "unknown"} {
		keep, dropped := FilterHints(nil, hints, bearer)
		if len(keep) != 2 || len(dropped) != 0 {
			t.Fatalf("bearer=%q: keep=%v dropped=%v; want all kept (conservative)", bearer, keep, dropped)
		}
	}
}
