package rules

func init() {
	Register(Rule{
		Name:     "apt29.beacon",
		Scenario: "apt29",
		Match: func(f Features) (bool, string) {
			return f.TLSDetected &&
				f.ServerName == "apt29-c2.local" &&
				f.Duration < 8 &&
				f.PeerGap >= 12 && f.PeerGap <= 34, ""
		},
	})
}
