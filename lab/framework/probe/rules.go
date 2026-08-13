package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"behinder-probe/rules"
)

type memHit struct {
	ts  float64
	src netip.Addr
}

type emitter struct {
	window      float64
	minMemFlows int
	jsonOut     bool
	reportJA3   bool
	scenarios   map[string]bool

	mu        sync.Mutex
	memHits   []memHit
	lastAgg   map[netip.Addr]float64
	ja3Seen   []ja3Hit
	lastJa3   map[netip.Addr]float64
	shortSeen []shortFlow
	lastGost  map[string]float64
	tlsShort  []shortFlow
	lastBurst map[string]float64
	deimosHits []memHit
	lastDeimos map[netip.Addr]float64
	gzHits     []memHit
	lastGz     map[netip.Addr]float64
	bfHits     []bfHit
	lastBf     map[string]float64
}

type ja3Hit struct {
	ts  float64
	src netip.Addr
	ja3 string
	dst netip.Addr
	dport uint16
}

// brute-force / port-scan detection: short, small flows from one source
// to the same dst port (conn burst) or across many ports (sweep).
const (
	bfWindowSec   = 10.0 // rolling window
	bfMinSamePort = 40   // connections to the same dst:port within window
	bfMinPorts    = 60   // distinct dst ports probed within window
)

type bfHit struct {
	ts    float64
	src   netip.Addr
	dst   netip.Addr
	dport uint16
	proto byte
}

func newEmitter(window float64, minMem int, jsonOut, reportJA3 bool) *emitter {
	return &emitter{
		window:      window,
		minMemFlows: minMem,
		jsonOut:     jsonOut,
		reportJA3:   reportJA3,
		scenarios:   nil,
		lastAgg:     make(map[netip.Addr]float64),
		lastJa3:     make(map[netip.Addr]float64),
		lastGost:    make(map[string]float64),
		lastBurst:   make(map[string]float64),
		lastDeimos:  make(map[netip.Addr]float64),
		lastGz:      make(map[netip.Addr]float64),
		lastBf:      make(map[string]float64),
	}
}

type shortFlowAgg struct {
	scenario string
	event    string
	lo, hi   float64
	note     string
}

type shortFlow struct {
	ts       float64
	src, dst netip.Addr
	dport    uint16
	resp     int
	firstC   int
}

func (e *emitter) emit(event string, fields map[string]any) {
	fields["event"] = event
	fields["ts"] = float64(time.Now().UnixNano()) / 1e9
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.jsonOut {
		b, _ := json.Marshal(fields)
		fmt.Fprintln(os.Stdout, string(b))
	} else {
		loc := fmt.Sprintf("%s:%d -> %s:%d",
			fields["src_ip"], fields["sport"], fields["dst_ip"], fields["dport"])
		fmt.Fprintf(os.Stdout, "[%s] %-28s %s\n",
			time.Now().Format("15:04:05"), event, loc)
	}
}

// onScored emits one alert per matching registered rule.
func (e *emitter) onScored(s scoredFlow, now float64, hits []rules.Rule) {
	src := s.src.String()
	dst := s.dst.String()
	for _, r := range hits {
		switch r.Name {
		case "behinder.mem_shell_flow":
			e.emit(r.Name, map[string]any{
				"src_ip": src, "sport": s.srcP, "dst_ip": dst, "dport": s.dstP,
				"exchanges": s.feat.exchanges, "records": s.feat.records,
				"req_bytes": s.feat.reqBytes, "resp_bytes": s.feat.respBytes,
				"big_req": s.feat.bigReq, "duration": round2(s.feat.duration),
			})
			e.mu.Lock()
			e.memHits = append(e.memHits, memHit{now, s.src})
			e.mu.Unlock()
		case "behinder.file_webshell_flow":
			e.emit(r.Name, map[string]any{
				"src_ip": src, "sport": s.srcP, "dst_ip": dst, "dport": s.dstP,
				"exchanges": s.feat.exchanges, "records": s.feat.records,
				"req_bytes": s.feat.reqBytes, "resp_bytes": s.feat.respBytes,
				"chunks_8225": s.feat.chunks8225,
			})
		case "ligolo.tunnel_heartbeat":
			e.emit(r.Name, map[string]any{
				"src_ip": src, "sport": s.srcP, "dst_ip": dst, "dport": s.dstP,
				"duration": round2(s.feat.duration),
				"small_c":  s.feat.smallC, "small_s": s.feat.smallS,
				"interval_c": round2(s.feat.intervalC),
				"interval_s": round2(s.feat.intervalS),
				"tls13":      s.feat.tls13,
				"note":       "periodic ~29B yamux heartbeats, TLS 1.3 AES-128-GCM",
			})
		case "deimos.checkin":
			e.emit(r.Name, map[string]any{
				"src_ip": src, "sport": s.srcP, "dst_ip": dst, "dport": s.dstP,
				"duration": round2(s.feat.duration),
				"first_c":  s.feat.firstC, "first_s": s.feat.firstS,
				"note": "8B length + 256B RSA-OAEP + AES-CBC, periodic short check-in",
			})
			e.mu.Lock()
			e.deimosHits = append(e.deimosHits, memHit{now, s.src})
			e.mu.Unlock()
		case "godzilla.payload_upload", "godzilla.php_flow":
			e.emit(r.Name, map[string]any{
				"src_ip": src, "sport": s.srcP, "dst_ip": dst, "dport": s.dstP,
				"duration": round2(s.feat.duration),
				"raw_c":    s.feat.rawCBytes, "raw_s": s.feat.rawSBytes,
				"note": "short HTTP POST flow, XOR+base64 body, md5-wrapped response",
			})
			e.mu.Lock()
			e.gzHits = append(e.gzHits, memHit{now, s.src})
			e.mu.Unlock()
		default:
			e.emit(r.Name, map[string]any{
				"src_ip": src, "sport": s.srcP, "dst_ip": dst, "dport": s.dstP,
				"duration": round2(s.feat.duration),
				"records":  s.feat.records,
				"small_c":  s.feat.smallC, "small_s": s.feat.smallS,
				"interval_c":  round2(s.feat.intervalC),
				"interval_s":  round2(s.feat.intervalS),
				"raw_small_c": s.feat.rawSmallC, "raw_small_s": s.feat.rawSmallS,
				"raw_interval_c": round2(s.feat.rawIntervalC),
				"raw_interval_s": round2(s.feat.rawIntervalS),
				"first_c":        s.feat.firstC, "first_s": s.feat.firstS,
				"tls13": s.feat.tls13,
			})
		}
	}
	if e.reportJA3 && s.ja3 != "" {
		e.emit("tls.ja3_signal", map[string]any{
			"src_ip": src, "ja3": s.ja3,
			"note": "low-confidence: shared by normal Java/OkHttp clients",
		})
	}
	if s.ja3 != "" {
		// track JA3s for the randomization aggregation regardless of -ja3
		e.mu.Lock()
		e.ja3Seen = append(e.ja3Seen, ja3Hit{now, s.src, s.ja3, s.dst, s.dstP})
		e.mu.Unlock()
	}
	// gost-style periodic short relay flows: non-TLS short flows with small
	// bidirectional payloads
	if !s.feat.tlsDetected && s.feat.duration < 5 &&
		s.feat.rawBytes > 0 && s.feat.rawBytes <= 2000 &&
		s.feat.rawSmallC >= 1 && s.feat.rawSmallS >= 1 {
		ts := now
		if s.first > 0 {
			ts = s.first
		}
		e.mu.Lock()
		e.shortSeen = append(e.shortSeen, shortFlow{ts, s.src, s.dst, s.dstP, 0, s.feat.firstC})
		e.mu.Unlock()
	}
	if s.feat.tlsDetected && s.feat.duration < 5 {
		ts := now
		if s.first > 0 {
			ts = s.first
		}
		e.mu.Lock()
		e.tlsShort = append(e.tlsShort, shortFlow{ts, s.src, s.dst, s.dstP, s.feat.respBytes, s.feat.firstC})
		e.mu.Unlock()
	}
	// brute-force / scan candidates: very short flows with little or no
	// payload (SSH/HTTP login attempts, SYN probes)
	if s.feat.duration < 2.0 && s.feat.rawBytes < 1000 {
		ts := now
		if s.first > 0 {
			ts = s.first
		}
		e.mu.Lock()
		proto := byte(6)
		if s.feat.isUDP {
			proto = 17
		}
		e.bfHits = append(e.bfHits, bfHit{ts, s.src, s.dst, s.dstP, proto})
		e.mu.Unlock()
	}
}

func (e *emitter) aggregate(now float64) {
	// --- brute-force / port scan ---
	e.mu.Lock()
	// loose wall-clock prune (memory), then a hit-time-relative window so
	// pcap replay with compressed timestamps is evaluated fairly
	wc := now - 2*bfWindowSec
	keptBf := e.bfHits[:0]
	for _, h := range e.bfHits {
		if h.ts >= wc {
			keptBf = append(keptBf, h)
		}
	}
	e.bfHits = keptBf
	maxTs := 0.0
	for _, h := range keptBf {
		if h.ts > maxTs {
			maxTs = h.ts
		}
	}
	cut := maxTs - bfWindowSec
	counted := keptBf[:0]
	for _, h := range keptBf {
		if h.ts >= cut {
			counted = append(counted, h)
		}
	}
	samePort := map[string][]bfHit{}
	bfByPair := map[string]map[uint16]bool{}
	for _, h := range counted {
		if h.proto != 6 { // brute force / sweep are TCP behaviours
			continue
		}
		k := h.src.String() + "|" + h.dst.String() + "|" + strconv.Itoa(int(h.dport))
		samePort[k] = append(samePort[k], h)
		pk := h.src.String() + "|" + h.dst.String()
		if bfByPair[pk] == nil {
			bfByPair[pk] = map[uint16]bool{}
		}
		bfByPair[pk][h.dport] = true
	}
	e.mu.Unlock()
	if e.scenarios["bruteforce"] {
		for k, hits := range samePort {
			if len(hits) >= bfMinSamePort && now-e.lastBf[k] >= bfWindowSec {
				e.lastBf[k] = now
				e.emit("bruteforce.conn_burst", map[string]any{
					"src_ip": hits[0].src.String(),
					"dst_ip": hits[0].dst.String(),
					"dport":  hits[0].dport,
					"conns":  len(hits), "window": int(bfWindowSec),
					"note": "many short small connections to the same dst port (brute force)",
				})
			}
		}
		for pk, ports := range bfByPair {
			if len(ports) >= bfMinPorts && now-e.lastBf["sweep|"+pk] >= bfWindowSec {
				e.lastBf["sweep|"+pk] = now
				src, dst, _ := strings.Cut(pk, "|")
				e.emit("bruteforce.port_sweep", map[string]any{
					"src_ip": src, "dst_ip": dst,
					"ports":  len(ports), "window": int(bfWindowSec),
					"note": "short flows to many distinct dst ports (port scan)",
				})
			}
		}
	}
	e.mu.Lock()
	cutoff := now - e.window
	kept := e.memHits[:0]
	for _, h := range e.memHits {
		if h.ts >= cutoff {
			kept = append(kept, h)
		}
	}
	e.memHits = kept
	counts := make(map[netip.Addr]int)
	for _, h := range e.memHits {
		counts[h.src]++
	}
	type alert struct {
		src netip.Addr
		n   int
	}
	var alerts []alert
	for src, n := range counts {
		if n >= e.minMemFlows && now-e.lastAgg[src] >= e.window {
			e.lastAgg[src] = now
			alerts = append(alerts, alert{src, n})
		}
	}
	e.mu.Unlock()
	if e.scenarios["behinder"] {
	for _, a := range alerts {
		e.emit("behinder.memory_shell_aggregate", map[string]any{
			"src_ip": a.src.String(), "flows": a.n, "window": int(e.window),
			"note": "short single-exchange TLS flows with big request chunks",
		})
	}
	}

	// deimos: >=3 short RSA+AES check-in flows from one source within the
	// window (the agent dials a fresh connection every ~15s).
	e.mu.Lock()
	dCutoff := now - e.window
	keptD := e.deimosHits[:0]
	for _, h := range e.deimosHits {
		if h.ts >= dCutoff {
			keptD = append(keptD, h)
		}
	}
	e.deimosHits = keptD
	dCounts := make(map[netip.Addr]int)
	for _, h := range e.deimosHits {
		dCounts[h.src]++
	}
	var dAlerts []alert
	for src, n := range dCounts {
		if n >= 3 && now-e.lastDeimos[src] >= e.window {
			e.lastDeimos[src] = now
			dAlerts = append(dAlerts, alert{src, n})
		}
	}
	e.mu.Unlock()
	if e.scenarios["deimos"] {
	for _, a := range dAlerts {
		e.emit("deimos.periodic_checkin", map[string]any{
			"src_ip": a.src.String(), "flows": a.n, "window": int(e.window),
			"note": "periodic short RSA+AES check-in flows (DeimosC2 agent)",
		})
	}
	}

	// godzilla: >=2 short HTTP webshell flows from one source within the
	// window (payload upload + method calls, human-paced).
	e.mu.Lock()
	gCutoff := now - e.window
	keptG := e.gzHits[:0]
	for _, h := range e.gzHits {
		if h.ts >= gCutoff {
			keptG = append(keptG, h)
		}
	}
	e.gzHits = keptG
	gCounts := make(map[netip.Addr]int)
	for _, h := range e.gzHits {
		gCounts[h.src]++
	}
	var gAlerts []alert
	for src, n := range gCounts {
		if n >= 2 && now-e.lastGz[src] >= e.window {
			e.lastGz[src] = now
			gAlerts = append(gAlerts, alert{src, n})
		}
	}
	e.mu.Unlock()
	if e.scenarios["godzilla"] {
	for _, a := range gAlerts {
		e.emit("godzilla.interactive_session", map[string]any{
			"src_ip": a.src.String(), "flows": a.n, "window": int(e.window),
			"note": "multiple short HTTP webshell flows (Godzilla php_xor_base64)",
		})
	}
	}

	// suo5 JA3 randomization: v1.1+ randomizes the TLS ClientHello per
	// handshake, so many short flows from one source with several distinct
	// JA3s is a strong signal.
	e.mu.Lock()
	ja3Cutoff := now - e.window
	keptJa3 := e.ja3Seen[:0]
	for _, h := range e.ja3Seen {
		if h.ts >= ja3Cutoff {
			keptJa3 = append(keptJa3, h)
		}
	}
	e.ja3Seen = keptJa3
	// suo5 (v1.1+) randomizes the TLS ClientHello per handshake: cipher
	// suite ORDER differs across flows. Normal Java/OkHttp clients only vary
	// extensions (e.g. resumption), so compare the cipher-suite field only.
	bySrc := map[string]map[string]bool{}
	srcOf := map[string]netip.Addr{}
	for _, h := range e.ja3Seen {
		key := h.src.String() + "|" + h.dst.String() + "|" + strconv.Itoa(int(h.dport))
		if bySrc[key] == nil {
			bySrc[key] = map[string]bool{}
			srcOf[key] = h.src
		}
		bySrc[key][ja3Ciphers(h.ja3)] = true
	}
	nFlows := map[string]int{}
	for _, h := range e.ja3Seen {
		key := h.src.String() + "|" + h.dst.String() + "|" + strconv.Itoa(int(h.dport))
		nFlows[key]++
	}
	e.mu.Unlock()
	if e.scenarios["suo5"] {
	for key, ja3s := range bySrc {
		src := srcOf[key]
		if nFlows[key] >= 3 && len(ja3s) >= 2 &&
			now-e.lastJa3[src] >= e.window {
			e.lastJa3[src] = now
			e.emit("suo5.ja3_randomization", map[string]any{
				"src_ip": src.String(), "flows": nFlows[key],
				"distinct_ja3": len(ja3s), "window": int(e.window),
				"note": "many TLS flows with rotating ClientHello fingerprints (suo5 v1.1+)",
			})
		}
	}
	}

	e.mu.Lock()
	sc := now - e.window
	keptShort := e.shortSeen[:0]
	for _, h := range e.shortSeen {
		if h.ts >= sc {
			keptShort = append(keptShort, h)
		}
	}
	e.shortSeen = keptShort
	byPair := map[string][]float64{}
	for _, h := range e.shortSeen {
		key := h.src.String() + "|" + h.dst.String() + "|" + strconv.Itoa(int(h.dport))
		byPair[key] = append(byPair[key], h.ts)
	}
	e.mu.Unlock()

	aggs := []shortFlowAgg{
		{"gost", "gost.tunnel_relay", 5, 15,
			"periodic short ws relay flows (gost tunnel usage)"},
		{"weevely", "weevely.interactive_shell", 2, 30,
			"repeated short HTTP flows to one endpoint (interactive webshell session)"},
	}
	for _, agg := range aggs {
		if !e.scenarios[agg.scenario] {
			continue
		}
		for key, times := range byPair {
			if len(times) < 3 {
				continue
			}
			sort.Float64s(times)
			gaps := make([]float64, 0, len(times)-1)
			for i := 1; i < len(times); i++ {
				if g := times[i] - times[i-1]; g > 1 {
					gaps = append(gaps, g)
				}
			}
			if len(gaps) == 0 {
				continue
			}
			sort.Float64s(gaps)
			med := gaps[len(gaps)/2]
			dedup := e.lastGost
			if agg.scenario != "gost" {
				dedup = e.lastBurst
			}
			if med >= agg.lo && med <= agg.hi && now-dedup[key] >= e.window {
				dedup[key] = now
				src, rest, _ := strings.Cut(key, "|")
				_, _, _ = strings.Cut(rest, "|")
				e.emit(agg.event, map[string]any{
					"src_ip": src, "flows": len(times),
					"interval": round2(med), "window": int(e.window),
					"note": agg.note,
				})
			}
		}
	}

	// TLS short-flow burst: meterpreter (and similar C2) opens a burst of
	// short TLS connections to the same endpoint during session init.
	e.mu.Lock()
	burstCutoff := now - 10
	keptTLS := e.tlsShort[:0]
	for _, h := range e.tlsShort {
		if h.ts >= burstCutoff {
			keptTLS = append(keptTLS, h)
		}
	}
	e.tlsShort = keptTLS
	burstCount := map[string]struct {
		src netip.Addr
		n   int
	}{}
	for _, h := range e.tlsShort {
		if h.resp > 100 || h.firstC > 1000 {
			// real page loads carry larger responses and browser-sized
			// ClientHello; meterpreter flows are tiny (~128B)
			continue
		}
		key := h.src.String() + "|" + h.dst.String() + "|" + strconv.Itoa(int(h.dport))
		b := burstCount[key]
		b.src = h.src
		b.n++
		burstCount[key] = b
	}
	e.mu.Unlock()
	for key, b := range burstCount {
		if b.n >= 15 && now-e.lastBurst[key] >= e.window {
			e.lastBurst[key] = now
			e.emit("metasploit.meterpreter", map[string]any{
				"src_ip": b.src.String(), "flows": b.n,
				"window": 10,
				"note": "burst of short TLS connections to one endpoint (C2 session init)",
			})
		}
	}
}

// ja3Ciphers returns the cipher-suite field of a JA3 string
// (format: version,ciphers,extensions,groups,ecpf).
func ja3Ciphers(ja3 string) string {
	for i, c := range ja3 {
		if c == ',' {
			if i+1 < len(ja3) {
				for j := i + 1; j < len(ja3); j++ {
					if ja3[j] == ',' {
						return ja3[i+1 : j]
					}
				}
				return ja3[i+1:]
			}
			break
		}
	}
	return ja3
}

func toRulesFeatures(f flowFeatures) rules.Features {
	return rules.Features{
		Exchanges:    f.exchanges,
		Records:      f.records,
		ReqBytes:     f.reqBytes,
		RespBytes:    f.respBytes,
		BigReq:       f.bigReq,
		Chunks8225:   f.chunks8225,
		Duration:     f.duration,
		SmallC:       f.smallC,
		SmallS:       f.smallS,
		IntervalC:    f.intervalC,
		IntervalS:    f.intervalS,
		TLS13:        f.tls13,
		RawSmallC:    f.rawSmallC,
		RawSmallS:    f.rawSmallS,
		RawIntervalC: f.rawIntervalC,
		RawIntervalS: f.rawIntervalS,
		RawCBytes:    f.rawCBytes,
		RawSBytes:    f.rawSBytes,
		HasProfilePost: f.hasProfilePost,
		HasC2QueryParam: f.hasC2QueryParam,
		HasLongCookie: f.hasLongCookie,
		HasChopperParam: f.hasChopperParam,
		ServerName:    f.serverName,
		RawClient:     f.rawClient,
		PeerGap:       f.peerGap,
		IsUDP:         f.isUDP,
		FirstC:       f.firstC,
		FirstS:       f.firstS,
		TLSDetected:  f.tlsDetected,
		ExchInterval: f.exchInterval,
	}
}

func round2(v float64) float64 {
	return float64(int(v*100+0.5)) / 100
}
