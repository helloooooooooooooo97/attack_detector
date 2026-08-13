package rules

func init() {
	Register(Rule{
		Name:     "ghostwriter.poll",
		Scenario: "ghostwriter",
		Match: func(f Features) (bool, string) {
			return f.TLSDetected &&
				f.ServerName == "drive.ghostwriter.local" &&
				f.Duration < 8 &&
				f.PeerGap >= 13 && f.PeerGap <= 37, ""
		},
	})
}
