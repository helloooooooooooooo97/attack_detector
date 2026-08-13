package rules

func init() {
	// Platypus agent keeps a persistent TLS link to the ingress and
	// exchanges periodic small RPC messages (sys_info, keepalives).
	Register(Rule{
		Name:     "platypus.link",
		Scenario: "platypus",
		Match: func(f Features) (bool, string) {
			return f.TLSDetected && f.Duration >= 30 &&
				f.RawSmallC >= 2 && f.RawSmallS >= 2 &&
				f.RawIntervalC >= 2 && f.RawIntervalC <= 40 &&
				f.RawIntervalS >= 2 && f.RawIntervalS <= 40 &&
				f.RawIntervalC > 0 && f.RawIntervalS > 0 &&
				abs(f.RawIntervalC-f.RawIntervalS) <= 4, ""
		},
	})
}

func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}
