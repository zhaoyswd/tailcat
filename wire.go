// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailcat

import (
	"errors"
	"fmt"
	"net/netip"

	"tailscale.com/tailcfg"
)

// This file defines the CBOR wire types behind [Addr]. They mirror the
// subset of [ConnInfo] and the tailcfg DERP types that tailcat actually
// uses, with single-character CBOR field names and omitempty so that addresses
// with embedded DERP regions stay short. Having our own types also keeps
// the wire format independent of upstream tailcfg changes.
//
// The short CBOR field names are the wire format: do not change or reuse
// them. Each is globally unique across all the wire types here (one short
// name per Go field name and vice versa), which TestWireFieldNames locks
// in.

// The JSON tags are only for display (see [ParseAddrRaw]); they
// mirror the Go field names but omit empty fields, so the JSON shows
// just what the CBOR actually carries.

// wireConnInfo is the wire form of [ConnInfo].
type wireConnInfo struct {
	ServerPublic      NodePublic          `cbor:"p" json:"ServerPublic"`
	ServerDiscoPublic *DiscoPublic        `cbor:"k,omitempty" json:"ServerDiscoPublic,omitempty"`
	PresharedKey      *PresharedKey       `cbor:"q,omitempty" json:"PresharedKey,omitempty"`
	Region            []*wireRegion       `cbor:"r,omitempty" json:"Region,omitempty"`
	RegionID          int64               `cbor:"i,omitempty" json:"RegionID,omitempty"`
	EndpointHints     []*wireEndpointHint `cbor:"e,omitempty" json:"EndpointHints,omitempty"`
}

// wireEndpointHint is the wire form of [EndpointHint]: a direct-connect
// candidate for the server, as observed by the server itself. The wire
// AddrPort uses netip.AddrPort's string form ("1.2.3.4:443" or
// "[2606::1]:443").
type wireEndpointHint struct {
	// AddrPort is the candidate's public IP and port.
	AddrPort string `cbor:"a" json:"AddrPort"`

	// Tier is the server's confidence in the candidate (see the
	// EndpointHintTier* constants): 1 trusted, 2 best-effort, 3 manual.
	Tier int `cbor:"T" json:"Tier"`

	// Generated is when the server observed the candidate, as unix
	// seconds. Zero means unknown; clients treat it as fresh.
	Generated int64 `cbor:"g,omitempty" json:"Generated,omitempty"`
}

// wireRegion is the wire form of [tailcfg.DERPRegion].
type wireRegion struct {
	RegionID   int64       `cbor:"i,omitempty" json:"RegionID,omitempty"`
	RegionCode string      `cbor:"c,omitempty" json:"RegionCode,omitempty"`
	RegionName string      `cbor:"m,omitempty" json:"RegionName,omitempty"`
	Nodes      []*wireNode `cbor:"N,omitempty" json:"Nodes,omitempty"`
}

// wireNode is the wire form of [tailcfg.DERPNode].
type wireNode struct {
	Name     string `cbor:"n,omitempty" json:"Name,omitempty"`
	RegionID int64  `cbor:"i,omitempty" json:"RegionID,omitempty"`
	HostName string `cbor:"h,omitempty" json:"HostName,omitempty"`

	// CertName is the expected TLS cert name when it differs from
	// HostName (which is used for the SNI). Empty means the cert is
	// expected to match HostName, as with [tailcfg.DERPNode.CertName];
	// the production DERP map sets it on no nodes today, so this is
	// usually absent.
	CertName string `cbor:"t,omitempty" json:"CertName,omitempty"`

	IPv4             string `cbor:"4,omitempty" json:"IPv4,omitempty"`
	IPv6             string `cbor:"6,omitempty" json:"IPv6,omitempty"`
	STUNPort         int    `cbor:"s,omitempty" json:"STUNPort,omitempty"`
	DERPPort         int    `cbor:"d,omitempty" json:"DERPPort,omitempty"`
	InsecureForTests bool   `cbor:"x,omitempty" json:"InsecureForTests,omitempty"`
}

// wireEndpointHintOf converts an [EndpointHint] to its wire form.
func wireEndpointHintOf(h EndpointHint) *wireEndpointHint {
	return &wireEndpointHint{
		AddrPort:  h.AddrPort.String(),
		Tier:      h.Tier,
		Generated: h.Generated,
	}
}

// endpointHint converts w back to an [EndpointHint]. The AddrPort string
// comes from untrusted input (a pasted address), so parse errors are
// reported rather than silently dropped.
func (w *wireEndpointHint) endpointHint() (EndpointHint, error) {
	if w == nil {
		return EndpointHint{}, errors.New("null endpoint hint")
	}
	ap, err := netip.ParseAddrPort(w.AddrPort)
	if err != nil {
		return EndpointHint{}, fmt.Errorf("invalid endpoint hint %q: %w", w.AddrPort, err)
	}
	if !ap.IsValid() || w.Tier == 0 {
		return EndpointHint{}, fmt.Errorf("invalid endpoint hint %q: bad tier or address", w.AddrPort)
	}
	return EndpointHint{AddrPort: ap, Tier: w.Tier, Generated: w.Generated}, nil
}

// wireRegionOf converts a [tailcfg.DERPRegion] (such as one from the
// control plane's DERP map) to its wire form. Fields tailcat doesn't
// use (Latitude, Longitude, CanPort80, ...) are dropped, as are
// STUN-only nodes: they can't relay DERP traffic, which is all an
// embedded region is for.
func wireRegionOf(r *tailcfg.DERPRegion) *wireRegion {
	w := &wireRegion{
		RegionID:   r.RegionID.Int64(),
		RegionCode: r.RegionCode,
		RegionName: r.RegionName,
	}
	for _, n := range r.Nodes {
		if n.STUNOnly {
			continue
		}
		w.Nodes = append(w.Nodes, &wireNode{
			Name:             n.Name,
			RegionID:         n.RegionID.Int64(),
			HostName:         n.HostName,
			CertName:         n.CertName,
			IPv4:             n.IPv4,
			IPv6:             n.IPv6,
			STUNPort:         n.STUNPort,
			DERPPort:         n.DERPPort,
			InsecureForTests: n.InsecureForTests,
		})
	}
	return w
}

// derpRegion converts w back to a [tailcfg.DERPRegion].
func (w *wireRegion) derpRegion() *tailcfg.DERPRegion {
	r := &tailcfg.DERPRegion{
		RegionID:   tailcfg.DERPRegionID(w.RegionID),
		RegionCode: w.RegionCode,
		RegionName: w.RegionName,
	}
	for _, n := range w.Nodes {
		r.Nodes = append(r.Nodes, &tailcfg.DERPNode{
			Name:             n.Name,
			RegionID:         tailcfg.DERPRegionID(n.RegionID),
			HostName:         n.HostName,
			CertName:         n.CertName,
			IPv4:             n.IPv4,
			IPv6:             n.IPv6,
			STUNPort:         n.STUNPort,
			DERPPort:         n.DERPPort,
			InsecureForTests: n.InsecureForTests,
		})
	}
	return r
}
