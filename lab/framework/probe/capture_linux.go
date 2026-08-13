//go:build linux

package main

import (
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"time"
)

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// liveCapture runs a raw AF_PACKET capture loop (no libpcap dependency).
// A background ticker evicts idle flows while recvfrom blocks.
func liveCapture(iface string, tr *tracker, process func([]scoredFlow, float64)) error {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return fmt.Errorf("socket(AF_PACKET): %w", err)
	}
	defer syscall.Close(fd)
	// Large receive buffer: burst tolerance on mirror/SPAN ports. The
	// kernel doubles the requested size; root can exceed rmem_max via
	// SO_RCVBUFFORCE.
	for _, opt := range []int{syscall.SO_RCVBUFFORCE, syscall.SO_RCVBUF} {
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, opt, 64<<20); err == nil {
			break
		}
	}

	ni, err := net.InterfaceByName(iface)
	if err != nil {
		return fmt.Errorf("interface %s: %w", iface, err)
	}
	ll := &syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_ALL),
		Ifindex:  ni.Index,
	}
	if err := syscall.Bind(fd, ll); err != nil {
		return fmt.Errorf("bind %s: %w", iface, err)
	}
	fmt.Fprintf(os.Stderr, "[probe] listening on %s (mirror/SPAN port)\n", iface)

	stop := make(chan struct{})
	go func() {
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		var lastFrames, lastFlows int
		for {
			select {
			case <-tick.C:
				now := nowSec()
				process(tr.evictIdle(now), now)
				tr.mu.Lock()
				flows := len(tr.flows)
				tr.mu.Unlock()
				frames := int(framesTotal.Load())
				fmt.Fprintf(os.Stderr,
					"[probe] frames=%d (+%d/s) flows=%d (+%d)\n",
					frames, frames-lastFrames, flows, flows-lastFlows)
				lastFrames = frames
				lastFlows = flows
			case <-stop:
				return
			}
		}
	}()

	buf := make([]byte, 65536)
	for {
		n, from, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			close(stop)
			return err
		}
		if n == 0 {
			continue
		}
		// On loopback each frame is delivered twice (once outgoing, once
		// received). Mirror/SPAN traffic arrives as HOST or OTHERHOST, so
		// dropping PACKET_OUTGOING dedups lo without losing mirrored frames.
		if ll, ok := from.(*syscall.SockaddrLinklayer); ok && ll.Pkttype == 4 {
			continue // PACKET_OUTGOING
		}
		framesTotal.Add(1)
		handleFrame(tr, nowSec(), buf[:n], 1) // AF_PACKET delivers Ethernet frames
	}
}

var framesTotal atomic.Int64
