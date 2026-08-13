package rules

func init() {
	Register(Rule{
		Name:     "aptc68.beacon",
		Scenario: "aptc68",
		Match: func(f Features) (bool, string) {
			return f.TLSDetected &&
				f.ServerName == "aptc68-c2.local" &&
				f.Duration < 8 &&
				f.PeerGap >= 9 && f.PeerGap <= 25, ""
		},
	})
}
