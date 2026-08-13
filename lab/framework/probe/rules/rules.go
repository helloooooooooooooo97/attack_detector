// Package rules: scenario plugin registry for the probe.
//
// Each scenario (behinder, ligolo, ...) registers its detection rule(s)
// here. The probe core (main.go / tracker.go) stays tool-agnostic.
package rules

// Features is the tool-agnostic flow feature vector extracted by the probe.
type Features struct {
	Exchanges  int     // request-response cycles on the flow
	Records    int     // total TLS records (all types, both directions)
	ReqBytes   int     // total request (client->server) appdata bytes
	RespBytes  int     // total response appdata bytes
	BigReq     int     // request records >= 8000B
	Chunks8225 int     // request records in [8000, 8500]
	Duration   float64 // flow duration (s)

	SmallC     int       // ~29B heartbeat-like records, client->server
	SmallS     int       // ~29B heartbeat-like records, server->client
	IntervalC  float64   // median gap between small client records (s)
	IntervalS  float64   // median gap between small server records (s)
	TLS13      bool      // negotiated cipher is TLS_AES_128_GCM_SHA256 (0x1301)

	RawSmallC    int     // small raw TCP payloads, client->server
	RawSmallS    int     // small raw TCP payloads, server->client
	RawIntervalC float64 // median gap between small raw client payloads (s)
	RawIntervalS float64 // median gap between small raw server payloads (s)
	FirstC       int     // size of first client payload
	FirstS       int     // size of first server payload
	TLSDetected  bool    // TLS handshake seen on this flow
	ExchInterval float64 // median gap between HTTP exchanges (s)
	RawCBytes    int     // total raw TCP payload bytes, client->server
	RawSBytes    int     // total raw TCP payload bytes, server->client
	HasProfilePost bool  // raw client payload carries a C2 HTTP profile POST marker
	HasC2QueryParam bool // raw client payload carries an encrypted C2 query param
	HasLongCookie   bool // raw client payload carries a very long Cookie header
	HasChopperParam bool // raw client payload carries China Chopper z0/z1 form params
	ServerName      string // SNI from the TLS ClientHello (e.g. ngrok agent)
	RawClient       string // first ~2KB of client->server raw payload (non-TLS markers)
	PeerGap         float64 // seconds since the previous flow from the same src|dst
	IsUDP           bool // transport is UDP (covert datagram channel)
}

// Rule is one scenario detection rule.
type Rule struct {
	Name     string // alert event name, e.g. "behinder.mem_shell_flow"
	Scenario string // scenario key, e.g. "behinder"
	Match    func(f Features) (bool, string)
}

var registry []Rule

// Register adds a rule. Called from scenario packages' init().
func Register(r Rule) {
	registry = append(registry, r)
}

// Enabled builds a scenario enable-set from a comma-separated flag value.
func Enabled(list string) map[string]bool {
	m := map[string]bool{}
	for _, s := range split(list) {
		m[s] = true
	}
	return m
}

// EnabledAll returns a set with every registered scenario enabled.
func EnabledAll() map[string]bool {
	m := map[string]bool{}
	for _, r := range registry {
		m[r.Scenario] = true
	}
	return m
}

// MatchAll returns all enabled rules that match the features.
func MatchAll(f Features, enabled map[string]bool) []Rule {
	var hits []Rule
	for _, r := range registry {
		if enabled[r.Scenario] {
			if ok, _ := r.Match(f); ok {
				hits = append(hits, r)
			}
		}
	}
	return hits
}

func split(s string) []string {
	var out []string
	cur := ""
	for _, c := range s {
		if c == ',' {
			if cur != "" {
				out = append(out, cur)
			}
			cur = ""
		} else {
			cur += string(c)
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
