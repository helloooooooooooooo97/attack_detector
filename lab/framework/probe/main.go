// Behinder (ice scorpion) real-time behavioral probe.
//
// Deploy on a Linux sensor attached to a switch mirror (SPAN/TAP) port.
// Captures live traffic via AF_PACKET TPACKET_V3 (gopacket/afpacket) with
// zero-copy semantics, parses minimal packet headers manually, reconstructs
// TLS flows, and applies the fingerprint rules validated in lab/detect.py:
//
//	R1  memory-shell pattern: many short flows, one exchange each, ~13 TLS
//	    records, big request chunks, request > response
//	R2  file-webshell pattern: one long-lived flow, many exchanges, constant
//	    ~8225B request chunks
//
// All features come from the encrypted-traffic side channel (TLS record
// headers, connection lifecycle, timing, JA3). No decryption is performed.
//
// Usage:
//
//	sudo ./behinder-probe -i eth0                 # live mirror port
//	./behinder-probe -r capture.pcap              # offline replay / testing
//	sudo ./behinder-probe -i eth0 -json           # JSON alert lines
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"behinder-probe/rules"
)

func nowSec() float64 {
	return float64(time.Now().UnixNano()) / 1e9
}

func main() {
	var (
		iface      = flag.String("i", "", "interface to listen on (mirror/SPAN port)")
		replay     = flag.String("r", "", "pcap file to replay instead of live capture")
		window     = flag.Float64("window", 60.0, "aggregation window in seconds")
		minMem     = flag.Int("min-mem-flows", 3, "min memory-shell flows per src within window")
		idle       = flag.Float64("idle", 30.0, "flow idle timeout in seconds")
		jsonOut    = flag.Bool("json", false, "emit alerts as JSON lines")
		reportJA3  = flag.Bool("ja3", true, "report low-confidence JA3 signals")
		maxFlows   = flag.Int("max-flows", 100000, "max tracked flows")
		debug      = flag.Bool("debug", false, "log every scored flow's features to stderr")
		scenario   = flag.String("scenario", "", "comma-separated scenarios to enable (default: all)")
	)
	flag.Parse()

	if *iface == "" && *replay == "" {
		fmt.Fprintln(os.Stderr, "need -i <iface> or -r <pcap>")
		os.Exit(2)
	}

	tr := newTracker(*idle, *maxFlows)
	enabled := rules.Enabled(*scenario)
	if len(enabled) == 0 {
		enabled = rules.EnabledAll()
	}
	em := newEmitter(*window, *minMem, *jsonOut, *reportJA3)
	em.scenarios = enabled

	process := func(scored []scoredFlow, now float64) {
		for _, s := range scored {
			if *debug {
				fmt.Fprintf(os.Stderr,
					"[debug] flow %s:%d -> %s:%d exch=%d recs=%d req=%d resp=%d big_req=%d chunks=%d dur=%.2f ja3=%t smallC=%d smallS=%d iC=%.1f iS=%.1f rawC=%d rawS=%d riC=%.1f riS=%.1f firstC=%d firstS=%d tls13=%t sni=%s gap=%.1f exi=%.1f rawCB=%d rawSB=%d\n",
					s.src, s.srcP, s.dst, s.dstP,
					s.feat.exchanges, s.feat.records, s.feat.reqBytes,
					s.feat.respBytes, s.feat.bigReq, s.feat.chunks8225,
					s.feat.duration, s.ja3 != "",
					s.feat.smallC, s.feat.smallS, s.feat.intervalC, s.feat.intervalS,
					s.feat.rawSmallC, s.feat.rawSmallS, s.feat.rawIntervalC, s.feat.rawIntervalS,
					s.feat.firstC, s.feat.firstS, s.feat.tls13,
					s.feat.serverName, s.feat.peerGap, s.feat.exchInterval,
					s.feat.rawCBytes, s.feat.rawSBytes)
			}
			hits := rules.MatchAll(toRulesFeatures(s.feat), enabled)
			em.onScored(s, now, hits)
		}
		em.aggregate(now)
	}

	var err error
	if *replay != "" {
		err = replayPcap(*replay, tr, process)
	} else {
		// Flush all in-flight flows on termination (the scenario runner
		// sends SIGTERM after its grace period) so long-lived connections
		// and UDP datagram channels are scored deterministically.
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
		go func() {
			<-sig
			process(tr.flushAll(nowSec()), nowSec())
			os.Exit(0)
		}()
		err = liveCapture(*iface, tr, process)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func handleFrame(tr *tracker, ts float64, data []byte, linktype int) {
	src, dst, sport, dport, proto, flags, payload, ok := parsePacket(data, linktype)
	if ok {
		tr.handlePacket(ts, src, sport, dst, dport, proto, flags, payload)
	}
}

// replayPcap feeds a classic pcap file through the same tracker (testing).
func replayPcap(path string, tr *tracker, process func([]scoredFlow, float64)) error {
	log.Printf("replaying %s", path)
	base := nowSec()
	var last float64
	err := readPcap(path, func(ts float64, data []byte, linktype int) {
		handleFrame(tr, base+ts, data, linktype)
		last = ts
	})
	if err != nil {
		return err
	}
	process(tr.flushAll(nowSec()), nowSec())
	log.Printf("replay done (%.2fs of traffic)", last)
	return nil
}
