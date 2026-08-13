package rules

func init() {
	// suo5 keeps an HTTP tunnel alive with a heartbeat every 5s (v2.x CLI:
	// "--no-heartbeat ... which will send data every 5s"). v1.1+ randomizes
	// the TLS ClientHello per handshake -> the JA3-randomization aggregation
	// in main.go complements this heartbeat rule.
	Register(Rule{
		Name:     "suo5.heartbeat",
		Scenario: "suo5",
		Match: func(f Features) (bool, string) {
			// suo5 tunnel runs over TLS; require it so real non-TLS
			// keepalive traffic is not flagged
			return f.TLSDetected &&
				f.FirstS <= 500 &&
				f.RawSmallC >= 1 && f.RawSmallS >= 1 &&
				f.RawIntervalC >= 2 && f.RawIntervalC <= 8 &&
				f.RawIntervalS >= 2 && f.RawIntervalS <= 8, ""
		},
	})
}
