package rules

func init() {
	Register(Rule{
		Name:     "evilox.checkin",
		Scenario: "evilox",
		Match: func(f Features) (bool, string) {
			return f.TLSDetected &&
				f.ServerName == "evilox-c2.local" &&
				f.Duration < 8 &&
				f.PeerGap >= 12 && f.PeerGap <= 34, ""
		},
	})
}
