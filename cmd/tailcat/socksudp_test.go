// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestSocks5UDPHeaderRoundTrip(t *testing.T) {
	payload := []byte("hello-udp")
	for _, dst := range []string{
		"1.2.3.4:53",
		"[2606:4700:4700::1111]:443",
	} {
		target := netip.MustParseAddrPort(dst)
		pkt, err := appendSocks5UDPHeader(nil, target)
		if err != nil {
			t.Fatalf("appendSocks5UDPHeader(%v): %v", target, err)
		}
		wantHdr := 10
		if target.Addr().Is6() {
			wantHdr = 22
		}
		if len(pkt) != wantHdr {
			t.Fatalf("头长度 = %d，want %d（%v）", len(pkt), wantHdr, target)
		}
		if got := socks5UDPEncapsulationLen(target); got != wantHdr {
			t.Errorf("socks5UDPEncapsulationLen(%v) = %d，want %d", target, got, wantHdr)
		}
		wire := append(append([]byte{}, pkt...), payload...)

		hdrLen, src, domain, frag, err := parseSocks5UDPHeader(wire)
		if err != nil {
			t.Fatalf("parseSocks5UDPHeader(%v): %v", target, err)
		}
		if hdrLen != wantHdr {
			t.Errorf("解析出的头长度 = %d，want %d", hdrLen, wantHdr)
		}
		if src != target {
			t.Errorf("解析出的目标 = %v，want %v", src, target)
		}
		if domain != "" {
			t.Errorf("解析出的域名 = %q，want 空", domain)
		}
		if frag != 0 {
			t.Errorf("FRAG = %d，want 0", frag)
		}
		if got := wire[hdrLen:]; !bytes.Equal(got, payload) {
			t.Errorf("净荷 = %q，want %q", got, payload)
		}
	}
}

func TestParseSocks5UDPHeaderDomain(t *testing.T) {
	// ATYP=3：长度前缀的域名（中继回复可能是这种形态，实测过）
	wire := []byte{0, 0, 0, socks5AtypDomain, 11}
	wire = append(wire, []byte("example.com")...)
	wire = binary.BigEndian.AppendUint16(wire, 443)
	wire = append(wire, "x"...)

	hdrLen, _, domain, frag, err := parseSocks5UDPHeader(wire)
	if err != nil {
		t.Fatalf("parseSocks5UDPHeader: %v", err)
	}
	if domain != "example.com" {
		t.Errorf("domain = %q，want example.com", domain)
	}
	if frag != 0 {
		t.Errorf("FRAG = %d，want 0", frag)
	}
	if hdrLen != len(wire)-1 {
		t.Errorf("头长度 = %d，want %d", hdrLen, len(wire)-1)
	}
}

func TestParseSocks5UDPHeaderFragAndErrors(t *testing.T) {
	v4 := []byte{0, 0, 0, socks5AtypIPv4, 1, 2, 3, 4, 0, 53}

	// FRAG≠0 必须被调用方看见（调用方按 RFC1928 丢弃）
	fragged := append([]byte{}, v4...)
	fragged[2] = 9
	if _, _, _, frag, err := parseSocks5UDPHeader(fragged); err != nil || frag != 9 {
		t.Errorf("FRAG 分片包：frag=%d err=%v，want frag=9 err=nil", frag, err)
	}

	// RSV 非零
	badRSV := append([]byte{}, v4...)
	badRSV[1] = 1
	if _, _, _, _, err := parseSocks5UDPHeader(badRSV); err == nil {
		t.Error("RSV 非零应当报错")
	}

	// 未知 ATYP
	badAtyp := append([]byte{}, v4...)
	badAtyp[3] = 0x09
	if _, _, _, _, err := parseSocks5UDPHeader(badAtyp); err == nil {
		t.Error("未知 ATYP 应当报错")
	}

	// 太短
	for _, n := range []int{0, 3, 6, 8} {
		if _, _, _, _, err := parseSocks5UDPHeader(v4[:n]); err == nil {
			t.Errorf("长度 %d 的包应当报错", n)
		}
	}

	// 域名长度超出实际数据
	short := []byte{0, 0, 0, socks5AtypDomain, 200, 'a'}
	if _, _, _, _, err := parseSocks5UDPHeader(short); err == nil {
		t.Error("域名长度越界应当报错")
	}
}

func TestAppendSocks5UDPHeaderRejectsUnspecified(t *testing.T) {
	if _, err := appendSocks5UDPHeader(nil, netip.AddrPort{}); err == nil {
		t.Error("零值目标地址应当报错")
	}
}

func TestParseForwardUDPMode(t *testing.T) {
	tests := []struct {
		in      string
		want    forwardUDPMode
		wantErr bool
	}{
		{"", forwardUDPAuto, false},
		{"auto", forwardUDPAuto, false},
		{"on", forwardUDPOn, false},
		{"off", forwardUDPOff, false},
		{"yes", "", true},
		{"AUTO", "", true},
	}
	for _, tt := range tests {
		got, err := parseForwardUDPMode(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("parseForwardUDPMode(%q) err=%v，wantErr=%v", tt.in, err, tt.wantErr)
			continue
		}
		if err == nil && got != tt.want {
			t.Errorf("parseForwardUDPMode(%q) = %q，want %q", tt.in, got, tt.want)
		}
	}
}
