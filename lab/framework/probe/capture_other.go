//go:build !linux

package main

import "errors"

// liveCapture is Linux-only (AF_PACKET); other platforms support replay only.
func liveCapture(iface string, tr *tracker, process func([]scoredFlow, float64)) error {
	return errors.New("live capture requires Linux (AF_PACKET); use -r to replay a pcap")
}
