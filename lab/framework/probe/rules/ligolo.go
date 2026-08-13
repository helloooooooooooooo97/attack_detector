package rules

func init() {
	Register(Rule{
		Name:     "ligolo.tunnel_heartbeat",
		Scenario: "ligolo",
		Match: func(f Features) (bool, string) {
			return rLigolo(f), ""
		},
	})
}

// rLigolo: TLS 1.3 (AES-128-GCM) long-lived tunnel with periodic ~29B
// yamux heartbeat records in both directions. Intervals: article version
// 27s/30s; v0.9 proxy 30s / agent 60s -> accept 20-70s.
func rLigolo(f Features) bool {
	return f.TLS13 &&
		f.SmallC >= 2 && f.SmallS >= 2 &&
		f.IntervalC >= 20 && f.IntervalC <= 70 &&
		f.IntervalS >= 20 && f.IntervalS <= 70 &&
		f.Duration >= 55
}
