// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package filter

import (
	"fmt"
	"strings"

	"inet.af/netaddr"
	"tailscale.com/wgengine/packet"
)

// PortRange is a range of TCP or UDP ports.
type PortRange struct {
	First, Last uint16 // the range is inclusive of First and Last.
}

func (pr PortRange) String() string {
	if pr.First == 0 && pr.Last == 65535 {
		return "*"
	} else if pr.First == pr.Last {
		return fmt.Sprintf("%d", pr.First)
	} else {
		return fmt.Sprintf("%d-%d", pr.First, pr.Last)
	}
}

// NetPortRange is a range of IPv4 addresses and TCP or UDP ports.
type NetPortRange struct {
	Net   netaddr.IPPrefix
	Ports PortRange
}

func (npr NetPortRange) String() string {
	return fmt.Sprintf("%v:%v", npr.Net, npr.Ports)
}

var (
	// NetAny is an IPPrefix that matches all IPv4 addresses.
	NetAny = netaddr.IPPrefix{
		IP:   netaddr.IPv4(0, 0, 0, 0),
		Bits: 0,
	}
	// NetNone is an IPPrefix that doesn't match any IPv4 or IPv6
	// address.
	NetNone = netaddr.IPPrefix{}
	// PortRangeAny matches any TCP/UDP port.
	PortRangeAny = PortRange{0, 65535}
	// NetPortRangeAny matches any IPv4 address and any TCP/UDP port.
	NetPortRangeAny = NetPortRange{NetAny, PortRangeAny}
)

// Match is a set of IPv4 source addresses combined with a set of
// destination NetPortRanges.
type Match struct {
	Dsts []NetPortRange
	Srcs []netaddr.IPPrefix
}

// Clone returns a deep copy of m.
func (m Match) Clone() (res Match) {
	res.Dsts = append([]NetPortRange{}, m.Dsts...)
	res.Srcs = append([]netaddr.IPPrefix{}, m.Srcs...)
	return res
}

func (m Match) String() string {
	srcs := []string{}
	for _, src := range m.Srcs {
		srcs = append(srcs, src.String())
	}
	dsts := []string{}
	for _, dst := range m.Dsts {
		dsts = append(dsts, dst.String())
	}

	var ss, ds string
	if len(srcs) == 1 {
		ss = srcs[0]
	} else {
		ss = "[" + strings.Join(srcs, ",") + "]"
	}
	if len(dsts) == 1 {
		ds = dsts[0]
	} else {
		ds = "[" + strings.Join(dsts, ",") + "]"
	}
	return fmt.Sprintf("%v=>%v", ss, ds)
}

// Marches is a set of packet matchers.
type Matches []Match

// Clone returns a deep copy of m.
func (m Matches) Clone() (res Matches) {
	for _, match := range m {
		res = append(res, match.Clone())
	}
	return res
}

// ipInList returns whether ip is in any of nets.
func ipInList(ip netaddr.IP, nets []netaddr.IPPrefix) bool {
	for _, net := range nets {
		if net.Contains(ip) {
			return true
		}
	}
	return false
}

// matchIPPorts returns whether q matches any of mm. Note that it does
// not check q's protocol, so its output only makes sense when q is an
// IPv4 TCP or UDP packet.
func matchIPPorts(mm Matches, q *packet.ParsedPacket) bool {
	for _, m := range mm {
		if !ipInList(q.Src.IP, m.Srcs) {
			continue
		}
		for _, dst := range m.Dsts {
			if !dst.Net.Contains(q.Dst.IP) {
				continue
			}
			if q.Dst.Port < dst.Ports.First || q.Dst.Port > dst.Ports.Last {
				continue
			}
			return true
		}
	}
	return false
}

// matchIPWithoutPorts returns whether q matches any of mm. Only src
// and dst IPs are checked, ports in both mm and q are ignored.
func matchIPWithoutPorts(mm Matches, q *packet.ParsedPacket) bool {
	for _, m := range mm {
		if !ipInList(q.Src.IP, m.Srcs) {
			continue
		}
		for _, dst := range m.Dsts {
			if !dst.Net.Contains(q.Dst.IP) {
				continue
			}
			return true
		}
	}
	return false
}
