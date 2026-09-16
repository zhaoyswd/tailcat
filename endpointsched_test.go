package tailcat

import (
	"net/netip"
	"testing"
	"time"
)

func schedHint(ap string, tier int) EndpointHint {
	return EndpointHint{AddrPort: netip.MustParseAddrPort(ap), Tier: tier, Generated: time.Now().Unix()}
}

func aps(list ...string) (out []netip.AddrPort) {
	for _, s := range list {
		out = append(out, netip.MustParseAddrPort(s))
	}
	return
}

func eqAPs(t *testing.T, got []netip.AddrPort, want []string) {
	t.Helper()
	w := aps(want...)
	if len(got) != len(w) {
		t.Fatalf("got %v; want %v", got, w)
	}
	for i := range got {
		if got[i] != w[i] {
			t.Fatalf("got %v; want %v", got, w)
		}
	}
}

func TestSortEndpointsCellular(t *testing.T) {
	hints := []EndpointHint{
		schedHint("192.168.3.12:41641", EndpointHintLAN),
		schedHint("114.242.60.128:41641", EndpointHintTrusted),
		schedHint("[2606:4700::1]:41641", EndpointHintBestEffort),
	}
	ordered, filtered := SortEndpoints(nil, hints, LocalNetInfo{Bearer: "cellular"})
	eqAPs(t, filtered, []string{"192.168.3.12:41641"})
	eqAPs(t, ordered, []string{"[2606:4700::1]:41641", "114.242.60.128:41641"})
}

func TestSortEndpointsWifiSamePrefix(t *testing.T) {
	hints := []EndpointHint{
		schedHint("114.242.60.128:41641", EndpointHintTrusted),
		schedHint("192.168.3.12:41641", EndpointHintLAN),
		schedHint("192.168.9.9:41641", EndpointHintLAN),
	}
	local := []netip.Prefix{netip.MustParsePrefix("192.168.3.99/24")}
	ordered, filtered := SortEndpoints(nil, hints, LocalNetInfo{Bearer: "wifi", Addrs: local})
	if len(filtered) != 0 {
		t.Fatalf("wifi filtered %v; want none", filtered)
	}
	// 同网段 LAN 最优先，公网按原序，异网段私网殿后。
	eqAPs(t, ordered, []string{"192.168.3.12:41641", "114.242.60.128:41641", "192.168.9.9:41641"})
}

func TestSortEndpointsLearnedFirst(t *testing.T) {
	hints := []EndpointHint{schedHint("114.242.60.128:41641", EndpointHintTrusted)}
	learned := aps("114.242.60.128:56016") // 端口漂移后学到的
	ordered, _ := SortEndpoints(learned, hints, LocalNetInfo{Bearer: "cellular"})
	eqAPs(t, ordered, []string{"114.242.60.128:56016", "114.242.60.128:41641"})
}

func TestSortEndpointsUnknownBearerConservative(t *testing.T) {
	hints := []EndpointHint{
		schedHint("114.242.60.128:41641", EndpointHintTrusted),
		schedHint("192.168.3.12:41641", EndpointHintLAN),
		schedHint("[2606:4700::1]:41641", EndpointHintBestEffort),
	}
	ordered, filtered := SortEndpoints(nil, hints, LocalNetInfo{})
	if len(filtered) != 0 {
		t.Fatalf("unknown bearer filtered %v; want none", filtered)
	}
	if len(ordered) != 3 {
		t.Fatalf("got %v", ordered)
	}
}

func TestSortEndpointsCGNATIsPrivate(t *testing.T) {
	hints := []EndpointHint{schedHint("100.64.5.5:41641", EndpointHintLAN)}
	_, filtered := SortEndpoints(nil, hints, LocalNetInfo{Bearer: "cellular"})
	eqAPs(t, filtered, []string{"100.64.5.5:41641"})
}
