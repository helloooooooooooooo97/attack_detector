package rules

func init() {
	Register(Rule{
		Name:     "hemao.beacon",
		Scenario: "hemao",
		Match: func(f Features) (bool, string) {
			return f.TLSDetected &&
				f.ServerName == "hemao-c2.local" &&
				f.Duration < 8 &&
				f.PeerGap >= 9 && f.PeerGap <= 25, ""
		},
	})
}
