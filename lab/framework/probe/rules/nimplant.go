package rules

func init() {
	// NimPlant v2 (Windows .NET implant, protocol-driven lab): HTTPS beacon
	// short flows, one checkin per connection, no keep-alive. Fixed SNI +
	// regular cross-flow interval are the stable fingerprints.
	Register(Rule{
		Name:     "nimplant.beacon",
		Scenario: "nimplant",
		Match: func(f Features) (bool, string) {
			return f.TLSDetected &&
				f.ServerName == "nimplant-c2.local" &&
				f.Duration < 6 &&
				f.PeerGap >= 8 && f.PeerGap <= 32 &&
				f.RawCBytes >= 400 && f.RawCBytes <= 4500, ""
		},
	})
}
