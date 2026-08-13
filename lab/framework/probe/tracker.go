package main

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Detection thresholds, calibrated on the lab captures (JDK11 + OkHttp 4.9.3).
const (
	exchangeGap    = 1.0   // seconds: max gap between records of one HTTP exchange
	bigRecordMin   = 8000  // bytes
	bigRecordMax   = 8500  // bytes (8225B chunk = okio 8192 + TLS overhead)
	maxTLSRecord   = 18000 // sanity bound for TLS record length
	maxRecordsFlow = 5000  // per-direction record cap per flow
	maxBufFlow     = 1 << 20
)

type endpoint struct {
	addr netip.Addr
	port uint16
}

type flowKey struct {
	a, b endpoint
	proto byte // 6 = TCP, 17 = UDP
}

func newKey(src netip.Addr, sport uint16, dst netip.Addr, dport uint16, proto byte) flowKey {
	a := endpoint{src, sport}
	b := endpoint{dst, dport}
	if b.addr.Compare(a.addr) < 0 || (b.addr == a.addr && b.port < a.port) {
		return flowKey{b, a, proto}
	}
	return flowKey{a, b, proto}
}

type tlsRec struct {
	typ    byte
	ts     float64
	length int
}

type tlsParser struct {
	buf  []byte
	recs []tlsRec
}

func (p *tlsParser) feed(ts float64, payload []byte, clientHello, serverHello *[]byte, isClient bool) {
	p.buf = append(p.buf, payload...)
	for len(p.buf) >= 5 {
		typ := p.buf[0]
		ln := int(binary.BigEndian.Uint16(p.buf[3:5]))
		if ln > maxTLSRecord {
			p.buf = p.buf[:0]
			return
		}
		if len(p.buf) < 5+ln {
			break
		}
		rec := p.buf[5 : 5+ln]
		if len(p.recs) < maxRecordsFlow {
			p.recs = append(p.recs, tlsRec{typ, ts, ln})
		}
		if isClient && typ == 22 && len(rec) > 0 && rec[0] == 1 &&
			*clientHello == nil && len(rec) <= 4096 {
			cp := make([]byte, len(rec))
			copy(cp, rec)
			*clientHello = cp
		}
		if !isClient && typ == 22 && len(rec) > 0 && rec[0] == 2 &&
			*serverHello == nil && len(rec) <= 4096 {
			cp := make([]byte, len(rec))
			copy(cp, rec)
			*serverHello = cp
		}
		p.buf = p.buf[5+ln:]
	}
	if len(p.buf) > maxBufFlow {
		p.buf = p.buf[:0]
	}
}

type flow struct {
	key         flowKey
	client      endpoint
	server      endpoint
	proto       byte
	first, last float64
	fins        int
	parsers     [2]tlsParser // 0 = client->server, 1 = server->client
	clientHello []byte
	serverHello []byte
	raw         [2][]rawChunk // raw TCP payloads (for non-TLS protocols)
	clientHead  []byte        // first bytes of client->server payloads
}

type rawChunk struct {
	ts   float64
	size int
}

type flowFeatures struct {
	exchanges  int
	records    int
	reqBytes   int
	respBytes  int
	bigReq     int
	chunks8225 int
	duration   float64

	smallC     int
	smallS     int
	intervalC  float64
	intervalS  float64
	tls13      bool

	rawSmallC    int
	rawSmallS    int
	rawIntervalC float64
	rawIntervalS float64
	rawCBytes    int
	rawSBytes    int
	hasProfilePost bool
	hasC2QueryParam bool
	hasLongCookie   bool
	hasChopperParam bool
	serverName      string
	peerGap         float64 // seconds since the previous flow from the same src|dst
	rawClient       string  // first ~2KB of client->server raw payload
	isUDP           bool    // transport is UDP (covert datagram channel)
	firstC       int // size of first client payload (stowaway 16B AuthToken)
	firstS       int // size of first server payload (AuthToken echo)
	tlsDetected  bool
	exchInterval float64 // median gap between HTTP exchanges (polling tools)
	rawBytes     int     // total raw TCP payload bytes (both directions)
}

type tracker struct {
	mu          sync.Mutex
	flows       map[flowKey]*flow
	idleTimeout float64
	maxFlows    int
	peerLast    map[string]float64 // "src|dst" -> last flow last-packet ts
}

func newTracker(idleTimeout float64, maxFlows int) *tracker {
	return &tracker{
		flows:       make(map[flowKey]*flow),
		idleTimeout: idleTimeout,
		maxFlows:    maxFlows,
		peerLast:    make(map[string]float64),
	}
}

func (t *tracker) handlePacket(ts float64, src netip.Addr, sport uint16,
	dst netip.Addr, dport uint16, proto byte, flags byte, payload []byte) {

	t.mu.Lock()
	defer t.mu.Unlock()
	key := newKey(src, sport, dst, dport, proto)
	if proto == 17 { // UDP: every datagram is data, no handshake/fin state
		f, ok := t.flows[key]
		if !ok {
			f = &flow{
				key:    key,
				client: endpoint{src, sport},
				server: endpoint{dst, dport},
				proto:  proto,
				first:  ts,
				last:   ts,
			}
			t.flows[key] = f
		}
		f.last = ts
		if len(payload) > 0 {
			dir := 1
			ep := endpoint{src, sport}
			if ep == f.client {
				dir = 0
			}
			if len(f.raw[dir]) < 4000 {
				f.raw[dir] = append(f.raw[dir], rawChunk{ts, len(payload)})
			}
			if dir == 0 && len(f.clientHead) < 2048 {
				room := 2048 - len(f.clientHead)
				if len(payload) < room {
					room = len(payload)
				}
				f.clientHead = append(f.clientHead, payload[:room]...)
			}
		}
		return
	}
	isSYN := flags&0x02 != 0 && flags&0x10 == 0
	if isSYN {
		f := &flow{
			key:    key,
			client: endpoint{src, sport},
			server: endpoint{dst, dport},
			proto:  proto,
			first:  ts,
			last:   ts,
		}
		t.flows[key] = f
		return
	}

	f, ok := t.flows[key]
	if !ok {
		f = &flow{
			key:    key,
			client: endpoint{src, sport},
			server: endpoint{dst, dport},
			proto:  proto,
			first:  ts,
			last:   ts,
		}
		t.flows[key] = f
	}
	f.last = ts
	if flags&0x01 != 0 {
		f.fins++
	}
	if len(payload) > 0 {
		dir := 1
		ep := endpoint{src, sport}
		if ep == f.client {
			dir = 0
			if len(f.clientHead) < 2048 {
				room := 2048 - len(f.clientHead)
				if len(payload) < room {
					room = len(payload)
				}
				f.clientHead = append(f.clientHead, payload[:room]...)
			}
		}
		f.parsers[dir].feed(ts, payload, &f.clientHello, &f.serverHello, dir == 0)
		if len(f.raw[dir]) < 4000 {
			f.raw[dir] = append(f.raw[dir], rawChunk{ts, len(payload)})
		}
	}
}

// evictIdle scores and removes flows idle longer than the timeout.
func (t *tracker) evictIdle(now float64) []scoredFlow {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []scoredFlow
	cutoff := now - t.idleTimeout
	for key, f := range t.flows {
		idle := now - f.last
		// evict when idle past the timeout, or shortly after the connection
		// closed (FIN seen) so detection is near real-time
		if idle >= cutoff || (f.fins > 0 && idle >= 2.0) {
			out = append(out, t.scoreAndEvict(key))
		}
	}
	if len(t.flows) > t.maxFlows {
		excess := len(t.flows) - t.maxFlows
		for key := range t.flows {
			if excess <= 0 {
				break
			}
			out = append(out, t.scoreAndEvict(key))
			excess--
		}
	}
	return out
}

func (t *tracker) flushAll(now float64) []scoredFlow {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []scoredFlow
	for key := range t.flows {
		out = append(out, t.scoreAndEvict(key))
	}
	return out
}

type scoredFlow struct {
	feat flowFeatures
	ja3  string
	src  netip.Addr
	srcP uint16
	dst  netip.Addr
	dstP uint16
	first float64
}

func (t *tracker) scoreAndEvict(key flowKey) scoredFlow {
	f, ok := t.flows[key]
	if !ok {
		return scoredFlow{}
	}
	delete(t.flows, key)
	feat := scoreFlow(f)
	peerKey := f.client.addr.String() + "|" + f.server.addr.String()
	if prev, ok := t.peerLast[peerKey]; ok {
		feat.peerGap = f.last - prev
	}
	t.peerLast[peerKey] = f.last
	return scoredFlow{
		feat: feat,
		ja3:  ja3FromClientHello(f.clientHello),
		src:  f.client.addr,
		srcP: f.client.port,
		dst:  f.server.addr,
		dstP: f.server.port,
		first: f.first,
	}
}

func scoreFlow(f *flow) flowFeatures {
	type appData struct {
		ts   float64
		dir  int
		size int
	}
	var app []appData
	for dir := 0; dir < 2; dir++ {
		for _, r := range f.parsers[dir].recs {
			if r.typ == 23 {
				app = append(app, appData{r.ts, dir, r.length})
			}
		}
	}
	sort.Slice(app, func(i, j int) bool { return app[i].ts < app[j].ts })

	type run struct {
		dir     int
		start   float64
		end     float64
		records int
		bytes   int
		sizes   []int
	}
	var runs []run
	for _, a := range app {
		if n := len(runs); n > 0 && runs[n-1].dir == a.dir &&
			a.ts-runs[n-1].end <= exchangeGap {
			r := &runs[n-1]
			r.records++
			r.bytes += a.size
			r.end = a.ts
			r.sizes = append(r.sizes, a.size)
		} else {
			runs = append(runs, run{
				dir: a.dir, start: a.ts, end: a.ts,
				records: 1, bytes: a.size, sizes: []int{a.size},
			})
		}
	}

	feat := flowFeatures{duration: f.last - f.first}
	// heartbeat-like small records (yamux ping: 12B frame + 1B type + 16B tag)
	for dir := 0; dir < 2; dir++ {
		var times []float64
		for _, r := range f.parsers[dir].recs {
			if r.typ == 23 && r.length >= 25 && r.length <= 33 &&
				r.ts-f.first > 3.0 {
				times = append(times, r.ts)
				if dir == 0 {
					feat.smallC++
				} else {
					feat.smallS++
				}
			}
		}
		if len(times) >= 2 {
			gaps := make([]float64, 0, len(times)-1)
			for i := 1; i < len(times); i++ {
				if g := times[i] - times[i-1]; g > 0.5 {
					gaps = append(gaps, g)
				}
			}
			if len(gaps) == 0 {
				continue
			}
			sort.Float64s(gaps)
			med := gaps[len(gaps)/2]
			if dir == 0 {
				feat.intervalC = med
			} else {
				feat.intervalS = med
			}
		}
	}
	feat.tls13 = serverCipher(f.serverHello) == 0x1301 // TLS_AES_128_GCM_SHA256
	feat.tlsDetected = f.clientHello != nil || f.serverHello != nil
	feat.serverName = sniFromClientHello(f.clientHello)
	feat.rawClient = string(f.clientHead)
	feat.isUDP = f.proto == 17

	// raw TCP payload features (work for non-TLS protocols: stowaway, natpass,
	// gost websocket, ...)
	for dir := 0; dir < 2; dir++ {
		var times []float64
		for i, c := range f.raw[dir] {
			if dir == 0 && i == 0 {
				feat.firstC = c.size
			}
			if dir == 1 && i == 0 {
				feat.firstS = c.size
			}
			// skip the first payload per direction (handshake/upgrade);
			// the rest are protocol frames / relayed small traffic
			if i > 0 && c.size >= 1 && c.size <= 400 {
				times = append(times, c.ts)
				if dir == 0 {
					feat.rawSmallC++
				} else {
					feat.rawSmallS++
				}
			}
		}
		if len(times) >= 2 {
			gaps := make([]float64, 0, len(times)-1)
			for i := 1; i < len(times); i++ {
				if g := times[i] - times[i-1]; g > 0.5 {
					gaps = append(gaps, g)
				}
			}
			if len(gaps) == 0 {
				continue
			}
			sort.Float64s(gaps)
			med := gaps[len(gaps)/2]
			if dir == 0 {
				feat.rawIntervalC = med
			} else {
				feat.rawIntervalS = med
			}
		}
	}

	var exchStarts []float64
	for i := 0; i+1 < len(runs); i++ {
		if runs[i].dir != 0 || runs[i+1].dir != 1 {
			continue
		}
		if runs[i].bytes < 1000 && runs[i+1].bytes < 1000 {
			continue // JSSE encrypted-Finished artifact, not an HTTP exchange
		}
		feat.exchanges++
		exchStarts = append(exchStarts, runs[i].start)
		feat.reqBytes += runs[i].bytes
		feat.respBytes += runs[i+1].bytes
		for _, s := range runs[i].sizes {
			if s >= bigRecordMin {
				feat.bigReq++
			}
			if s >= bigRecordMin && s <= bigRecordMax {
				feat.chunks8225++
			}
		}
		i++
	}
	if len(exchStarts) >= 2 {
		gaps := make([]float64, 0, len(exchStarts)-1)
		for i := 1; i < len(exchStarts); i++ {
			if g := exchStarts[i] - exchStarts[i-1]; g > 0.5 {
				gaps = append(gaps, g)
			}
		}
		if len(gaps) > 0 {
			sort.Float64s(gaps)
			feat.exchInterval = gaps[len(gaps)/2]
		}
	}
	feat.records = len(f.parsers[0].recs) + len(f.parsers[1].recs)
	for dir := 0; dir < 2; dir++ {
		for _, c := range f.raw[dir] {
			feat.rawBytes += c.size
			if dir == 0 {
				feat.rawCBytes += c.size
			} else {
				feat.rawSBytes += c.size
			}
		}
	}
	// C2 HTTP profile marker (Covenant DefaultHttpProfile style):
	// body "i=<32 hex>&data=<base64 JSON>" plus an ASPSESSIONID cookie.
	feat.hasProfilePost = bytes.Contains(f.clientHead, []byte("&data=")) &&
		bytes.Contains(f.clientHead, []byte("ASPSESSIONID"))
	// Mythic http profile style: GET /index?q=<base64> or POST /data with
	// an encrypted body.
	feat.hasC2QueryParam = bytes.Contains(f.clientHead, []byte("/index?q=")) ||
		bytes.Contains(f.clientHead, []byte("POST /data"))
	// China Chopper webshell style: form params named z0 (base64 PHP eval
	// payload) and/or z1 (operation argument).
	feat.hasChopperParam = bytes.Contains(f.clientHead, []byte("z0=")) ||
		bytes.Contains(f.clientHead, []byte("z1="))
	// Cobalt Strike-style beacon metadata: one short GET carrying a very
	// long Cookie header (base64 RSA-encrypted session key + agent info).
	if i := bytes.Index(f.clientHead, []byte("Cookie:")); i >= 0 {
		rest := f.clientHead[i+len("Cookie:"):]
		if nl := bytes.IndexByte(rest, '\n'); nl >= 0 {
			rest = rest[:nl]
		}
		feat.hasLongCookie = len(bytes.TrimSpace(rest)) >= 300
	}
	return feat
}

// sniFromClientHello extracts the server_name (SNI) extension from a TLS
// ClientHello (extension type 0). Returns "" when absent/unparseable.
func sniFromClientHello(p []byte) string {
	if len(p) < 5 || p[0] != 1 {
		return ""
	}
	msgLen := int(p[1])<<16 | int(p[2])<<8 | int(p[3])
	body := p[4:]
	if msgLen > len(body) {
		body = body[:len(body)]
	}
	if len(body) < 38 {
		return ""
	}
	pos := 2 + 32
	if pos >= len(body) {
		return ""
	}
	sidLen := int(body[pos])
	pos += 1 + sidLen
	if pos+2 > len(body) {
		return ""
	}
	csLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2 + csLen
	if pos >= len(body) {
		return ""
	}
	compLen := int(body[pos])
	pos += 1 + compLen
	if pos+2 > len(body) {
		return ""
	}
	extTotal := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	end := pos + extTotal
	if end > len(body) {
		end = len(body)
	}
	for pos+4 <= end {
		et := int(binary.BigEndian.Uint16(body[pos : pos+2]))
		elen := int(binary.BigEndian.Uint16(body[pos+2 : pos+4]))
		if pos+4+elen > end {
			break
		}
		data := body[pos+4 : pos+4+elen]
		if et == 0 && len(data) >= 5 && data[2] == 0 {
			nlen := int(binary.BigEndian.Uint16(data[3:5]))
			if 5+nlen <= len(data) {
				return string(data[5 : 5+nlen])
			}
		}
		pos += 4 + elen
	}
	return ""
}

// serverCipher extracts the negotiated cipher suite from a ServerHello
// handshake message.
func serverCipher(p []byte) int {
	if len(p) < 5 || p[0] != 2 {
		return 0
	}
	msgLen := int(p[1])<<16 | int(p[2])<<8 | int(p[3])
	if msgLen > len(p)-4 {
		return 0
	}
	body := p[4 : 4+msgLen]
	if len(body) < 39 { // version(2) + random(32) + sid_len(1) + sid(0) + cs(2)
		return 0
	}
	pos := 2 + 32
	sidLen := int(body[pos])
	pos += 1 + sidLen
	if pos+2 > len(body) {
		return 0
	}
	return int(binary.BigEndian.Uint16(body[pos : pos+2]))
}

// ja3FromClientHello parses the JA3 fingerprint from a TLS ClientHello
// handshake message (port of lab/analyze.py).
func ja3FromClientHello(p []byte) string {
	if len(p) < 5 || p[0] != 1 {
		return ""
	}
	msgLen := int(p[1])<<16 | int(p[2])<<8 | int(p[3])
	body := p[4:]
	if msgLen > len(body) {
		body = body[:len(body)]
	}
	if len(body) < 38 {
		return ""
	}
	ver := int(binary.BigEndian.Uint16(body[0:2]))
	pos := 2 + 32
	if pos >= len(body) {
		return ""
	}
	sidLen := int(body[pos])
	pos += 1 + sidLen
	if pos+2 > len(body) {
		return ""
	}
	csLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	if pos+csLen > len(body) {
		csLen = len(body) - pos
	}
	var ciphers []string
	for i := 0; i+1 < csLen; i += 2 {
		ciphers = append(ciphers, strconv.Itoa(int(binary.BigEndian.Uint16(body[pos+i:pos+i+2]))))
	}
	pos += csLen
	if pos >= len(body) {
		return ""
	}
	compLen := int(body[pos])
	pos += 1 + compLen

	ext := make(map[int][]byte)
	if pos+2 <= len(body) {
		extTotal := int(binary.BigEndian.Uint16(body[pos : pos+2]))
		pos += 2
		end := pos + extTotal
		if end > len(body) {
			end = len(body)
		}
		for pos+4 <= end {
			et := int(binary.BigEndian.Uint16(body[pos : pos+2]))
			elen := int(binary.BigEndian.Uint16(body[pos+2 : pos+4]))
			edata := body[pos+4 : pos+4+elen]
			if pos+4+elen > end {
				break
			}
			ext[et] = edata
			pos += 4 + elen
		}
	}

	var groups []string
	if gdata, ok := ext[10]; ok && len(gdata) >= 2 {
		glen := int(binary.BigEndian.Uint16(gdata[:2]))
		for i := 0; i+1 < glen && 2+i+2 <= len(gdata); i += 2 {
			groups = append(groups, strconv.Itoa(int(binary.BigEndian.Uint16(gdata[2+i:4+i]))))
		}
	}
	var ecpf []string
	if edata, ok := ext[11]; ok && len(edata) >= 1 {
		for _, b := range edata[1:] {
			ecpf = append(ecpf, strconv.Itoa(int(b)))
		}
	}
	extIDs := make([]int, 0, len(ext))
	for id := range ext {
		extIDs = append(extIDs, id)
	}
	sort.Ints(extIDs)
	var exts []string
	for _, id := range extIDs {
		exts = append(exts, strconv.Itoa(id))
	}
	return strings.Join([]string{
		strconv.Itoa(ver),
		strings.Join(ciphers, "-"),
		strings.Join(exts, "-"),
		strings.Join(groups, "-"),
		strings.Join(ecpf, "-"),
	}, ",")
}
