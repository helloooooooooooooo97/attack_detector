package rules

func init() {
	Register(Rule{
		Name:     "zloader.beacon",
		Scenario: "zloader",
		Match: func(f Features) (bool, string) {
			return f.TLSDetected &&
				f.ServerName == "zloader-c2.local" &&
				f.Duration < 8 &&
				f.PeerGap >= 9 && f.PeerGap <= 25, ""
		},
	})
}
