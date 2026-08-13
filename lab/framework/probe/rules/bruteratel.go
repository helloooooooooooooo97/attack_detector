package rules

func init() {
	// Brute Ratel C4 BADGER (closed-source, protocol-driven lab): HTTPS POST
	// beacon, one short flow per checkin, configurable sleep (lab 20s).
	Register(Rule{
		Name:     "bruteratel.beacon",
		Scenario: "bruteratel",
		Match: func(f Features) (bool, string) {
			return f.TLSDetected &&
				f.ServerName == "c4-bruteratel.local" &&
				f.Duration < 6 &&
				f.PeerGap >= 12 && f.PeerGap <= 40 &&
				f.RawCBytes >= 500 && f.RawCBytes <= 4500, ""
		},
	})
}
