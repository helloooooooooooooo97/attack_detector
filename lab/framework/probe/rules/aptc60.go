package rules

func init() {
	Register(Rule{
		Name:     "aptc60.poll",
		Scenario: "aptc60",
		Match: func(f Features) (bool, string) {
			return f.TLSDetected &&
				f.ServerName == "pan.aptc60.local" &&
				f.Duration < 8 &&
				f.PeerGap >= 12 && f.PeerGap <= 34, ""
		},
	})
}
