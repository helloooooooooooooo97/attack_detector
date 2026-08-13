package rules

func init() {
	// shadow-tls v3: TLS camouflage proxy. The client crafts a small
	// ClientHello (~240B, vs 500B+ for real browsers/curl) targeting a
	// real site's SNI, then splices the target's ServerHello. Both peers
	// exchange small fixed-size application records. Fingerprint comes from
	// the handshake sizes + record cadence on the client->server leg.
	Register(Rule{
		Name:     "shadowtls.camouflage",
		Scenario: "shadowtls",
		Match: func(f Features) (bool, string) {
			return f.TLSDetected &&
				f.FirstC >= 200 && f.FirstC <= 350 &&
				f.FirstS >= 100 && f.FirstS <= 250 &&
				f.Duration < 10 &&
				f.Records >= 8 && f.Records <= 24, ""
		},
	})
}
