package rules

func init() {
	Register(Rule{
		Name:     "lazarus.beacon",
		Scenario: "lazarus",
		Match: func(f Features) (bool, string) {
			return f.TLSDetected &&
				f.ServerName == "lazarus-c2.local" &&
				f.Duration < 8 &&
				f.PeerGap >= 15 && f.PeerGap <= 42, ""
		},
	})
}
