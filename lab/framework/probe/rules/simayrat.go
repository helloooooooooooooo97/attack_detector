package rules

func init() {
	// SiMayRAT (C# Windows agent, protocol-driven lab): HTTPS polling a
	// cloud-document-style C2 endpoint, fixed SNI, JSON-disguised payloads.
	Register(Rule{
		Name:     "simayrat.poll",
		Scenario: "simayrat",
		Match: func(f Features) (bool, string) {
			return f.TLSDetected &&
				f.ServerName == "docs.simayrat.local" &&
				f.Duration < 6 &&
				f.PeerGap >= 10 && f.PeerGap <= 25, ""
		},
	})
}
