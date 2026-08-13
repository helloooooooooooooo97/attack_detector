//go:build linux

package main

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
)

func htonsD(v uint16) uint16 { return v<<8 | v>>8 }

// Debug tool (standalone): counts bytes received on AF_PACKET for one interface.
// Build: GOOS=linux go build -o debug_afpacket debug_afpacket.go
func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: debug_afpacket <iface> [seconds]")
		return
	}
	iface := os.Args[1]
	secs := 8
	if len(os.Args) > 2 {
		fmt.Sscanf(os.Args[2], "%d", &secs)
	}

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htonsD(syscall.ETH_P_ALL)))
	if err != nil {
		panic(err)
	}
	defer syscall.Close(fd)
	ni, err := net.InterfaceByName(iface)
	if err != nil {
		panic(err)
	}
	ll := &syscall.SockaddrLinklayer{
		Protocol: htonsD(syscall.ETH_P_ALL),
		Ifindex:  ni.Index,
	}
	if err := syscall.Bind(fd, ll); err != nil {
		panic(err)
	}
	fmt.Printf("bound to %s (ifindex=%d)\n", iface, ni.Index)

	buf := make([]byte, 65536)
	total := 0
	pkts := 0
	start := time.Now()
	for time.Since(start) < time.Duration(secs)*time.Second {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			fmt.Println("recv err:", err)
			continue
		}
		total += n
		pkts++
		if pkts <= 5 {
			fmt.Printf("pkt %d bytes\n", n)
		}
	}
	fmt.Printf("done: %d packets, %d bytes\n", pkts, total)
}
