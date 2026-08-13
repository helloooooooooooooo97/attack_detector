package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"os"
)

// parsePacket extracts TCP/UDP info from a frame. linktype follows libpcap
// values: 1=Ethernet, 0=NULL/loopback, 101/12=RAW, 113=SLL, 276=SLL2.
func parsePacket(data []byte, linktype int) (
	src, dst netip.Addr, sport, dport uint16, proto byte, flags byte, payload []byte, ok bool) {

	var etherType uint16
	var off int
	switch linktype {
	case 1: // Ethernet
		if len(data) < 14 {
			return
		}
		etherType = binary.BigEndian.Uint16(data[12:14])
		off = 14
		if etherType == 0x8100 || etherType == 0x88a8 { // VLAN / QinQ
			if len(data) < off+4 {
				return
			}
			etherType = binary.BigEndian.Uint16(data[off+2 : off+4])
			off += 4
		}
	case 0: // BSD loopback: 4-byte family header
		off = 4
		if len(data) <= off {
			return
		}
		if data[off]>>4 == 4 {
			etherType = 0x0800
		} else {
			etherType = 0x86dd
		}
	case 12, 101: // RAW IP
		if len(data) < 1 {
			return
		}
		if data[0]>>4 == 4 {
			etherType = 0x0800
		} else {
			etherType = 0x86dd
		}
	case 113: // Linux cooked v1
		if len(data) < 16 {
			return
		}
		etherType = binary.BigEndian.Uint16(data[14:16])
		off = 16
	case 276: // Linux cooked v2
		if len(data) < 20 {
			return
		}
		etherType = binary.BigEndian.Uint16(data[0:2])
		off = 20
	default:
		return
	}
	return parseIP(data, off, etherType)
}

func parseIP(data []byte, off int, etherType uint16) (
	src, dst netip.Addr, sport, dport uint16, proto byte, flags byte, payload []byte, ok bool) {

	var l4 int
	switch etherType {
	case 0x0800: // IPv4
		if len(data) < off+20 || data[off]>>4 != 4 {
			return
		}
		ihl := int(data[off]&0x0f) * 4
		proto = data[off+9]
		if (proto != 6 && proto != 17) || len(data) < off+ihl+8 {
			return // TCP/UDP only
		}
		var s4, d4 [4]byte
		copy(s4[:], data[off+12:off+16])
		copy(d4[:], data[off+16:off+20])
		src = netip.AddrFrom4(s4)
		dst = netip.AddrFrom4(d4)
		l4 = off + ihl
	case 0x86dd: // IPv6 (no extension headers)
		if len(data) < off+40 || (data[off+6] != 6 && data[off+6] != 17) {
			return
		}
		proto = data[off+6]
		var s16, d16 [16]byte
		copy(s16[:], data[off+8:off+24])
		copy(d16[:], data[off+24:off+40])
		src = netip.AddrFrom16(s16)
		dst = netip.AddrFrom16(d16)
		l4 = off + 40
	default:
		return
	}
	if proto == 6 && len(data) < l4+20 {
		return
	}
	if proto == 17 && len(data) < l4+8 {
		return
	}
	sport = binary.BigEndian.Uint16(data[l4 : l4+2])
	dport = binary.BigEndian.Uint16(data[l4+2 : l4+4])
	if proto == 17 {
		ul := int(binary.BigEndian.Uint16(data[l4+4 : l4+6]))
		if ul < 8 || l4+ul > len(data) {
			return
		}
		payload = data[l4+8 : l4+ul]
		ok = true
		return
	}
	flags = data[l4+13]
	doff := int(data[l4+12]>>4) * 4
	if doff < 20 || len(data) < l4+doff {
		return
	}
	payload = data[l4+doff:]
	ok = true
	return
}

// readPcap reads a classic pcap file and calls fn for every packet.
func readPcap(path string, fn func(ts float64, data []byte, linktype int)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	var magic [4]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		return err
	}
	var endian binary.ByteOrder = binary.LittleEndian
	div := 1_000_000.0
	switch {
	case magic == [4]byte{0xd4, 0xc3, 0xb2, 0xa1}:
	case magic == [4]byte{0xa1, 0xb2, 0xc3, 0xd4}:
		endian = binary.BigEndian
	case magic == [4]byte{0x4d, 0x3c, 0xb2, 0xa1}:
		div = 1_000_000_000.0
	case magic == [4]byte{0xa1, 0xb2, 0x3c, 0x4d}:
		endian = binary.BigEndian
		div = 1_000_000_000.0
	default:
		return fmt.Errorf("unsupported pcap magic %x", magic)
	}

	var ghdr [20]byte
	if _, err := io.ReadFull(f, ghdr[:]); err != nil {
		return err
	}
	linktype := int(endian.Uint32(ghdr[16:20]))

	var phdr [16]byte
	for {
		if _, err := io.ReadFull(f, phdr[:]); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return nil
			}
			return err
		}
		tsSec := endian.Uint32(phdr[0:4])
		tsFrac := endian.Uint32(phdr[4:8])
		inclLen := endian.Uint32(phdr[8:12])
		data := make([]byte, inclLen)
		if _, err := io.ReadFull(f, data); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return nil // truncated final packet; treat as end of capture
			}
			return err
		}
		fn(float64(tsSec)+float64(tsFrac)/div, data, linktype)
	}
}
