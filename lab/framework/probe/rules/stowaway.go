package rules

func init() {
	// Stowaway (non-TLS TCP): pre-auth exchange is a 16-byte AuthToken sent
	// by the agent and echoed verbatim by the admin within ~1s
	// (AuthToken = MD5(secret)[:16]).
	Register(Rule{
		Name:     "stowaway.auth_token_handshake",
		Scenario: "stowaway",
		Match: func(f Features) (bool, string) {
			return !f.TLSDetected && f.FirstC == 16 && f.FirstS == 16, ""
		},
	})
	// plus the regular heartbeat on the established tunnel (the auth
	// 16B/16B exchange must be present on the same flow)
	Register(Rule{
		Name:     "stowaway.heartbeat",
		Scenario: "stowaway",
		Match: func(f Features) (bool, string) {
			return !f.TLSDetected &&
				f.FirstC == 16 && f.FirstS == 16 &&
				f.RawSmallC >= 1 && f.RawSmallS >= 1 &&
				f.RawIntervalC >= 2 && f.RawIntervalC <= 120 &&
				f.RawIntervalS >= 2 && f.RawIntervalS <= 120, ""
		},
	})
}
