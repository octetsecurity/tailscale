// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import "inet.af/netaddr"

// IPProto is either a real IP protocol (ITCP, UDP, ...) or an special value like Unknown.
// If it is a real IP protocol, its value corresponds to its IP protocol number.
type IPProto uint8

const (
	// Unknown represents an unknown or unsupported protocol; it's deliberately the zero value.
	Unknown IPProto = 0x00
	ICMP    IPProto = 0x01
	IGMP    IPProto = 0x02
	ICMPv6  IPProto = 0x3a
	TCP     IPProto = 0x06
	UDP     IPProto = 0x11
	// Fragment is a special value. It's not really an IPProto value
	// so we're using the unassigned 0xFF value.
	// TODO(dmytro): special values should be taken out of here.
	Fragment IPProto = 0xFF
)

func (p IPProto) String() string {
	switch p {
	case Fragment:
		return "Frag"
	case ICMP:
		return "ICMP"
	case UDP:
		return "UDP"
	case TCP:
		return "TCP"
	default:
		return "Unknown"
	}
}

// IPHeader represents an IP packet header.
type IPHeader struct {
	IPProto IPProto
	IPID    uint16
	SrcIP   netaddr.IP
	DstIP   netaddr.IP
}

const ipHeaderLength = 20

func (IPHeader) Len() int {
	return ipHeaderLength
}

func (h IPHeader) Marshal(buf []byte) error {
	if len(buf) < ipHeaderLength {
		return errSmallBuffer
	}
	if len(buf) > maxPacketLength {
		return errLargePacket
	}

	buf[0] = 0x40 | (ipHeaderLength >> 2) // IPv4
	buf[1] = 0x00                         // DHCP, ECN
	put16(buf[2:4], uint16(len(buf)))
	put16(buf[4:6], h.IPID)
	put16(buf[6:8], 0) // flags, offset
	buf[8] = 64        // TTL
	buf[9] = uint8(h.IPProto)
	put16(buf[10:12], 0) // blank IP header checksum
	src, dst := h.SrcIP.As4(), h.DstIP.As4()
	copy(buf[12:16], src[:])
	copy(buf[16:20], dst[:])

	put16(buf[10:12], ipChecksum(buf[0:20]))

	return nil
}

// MarshalPseudo serializes the header into buf in pseudo format.
// It clobbers the header region, which is the first h.Length() bytes of buf.
// It explicitly initializes every byte of the header region,
// so pre-zeroing it on reuse is not required. It does not allocate memory.
func (h IPHeader) MarshalPseudo(buf []byte) error {
	if len(buf) < ipHeaderLength {
		return errSmallBuffer
	}
	if len(buf) > maxPacketLength {
		return errLargePacket
	}

	length := len(buf) - ipHeaderLength
	src, dst := h.SrcIP.As4(), h.DstIP.As4()
	copy(buf[8:12], src[:])
	copy(buf[12:16], dst[:])
	buf[16] = 0x0
	buf[17] = uint8(h.IPProto)
	put16(buf[18:20], uint16(length))

	return nil
}

func (h *IPHeader) ToResponse() {
	h.SrcIP, h.DstIP = h.DstIP, h.SrcIP
	// Flip the bits in the IPID. If incoming IPIDs are distinct, so are these.
	h.IPID = ^h.IPID
}
