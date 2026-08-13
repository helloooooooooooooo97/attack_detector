package rules

func init() {
	// Merlin agent polls the server over HTTPS (h2) with JWE-encrypted POSTs
	// on a fixed sleep interval (default 30s). Each checkin is one HTTP
	// exchange -> periodic exchange starts.
	Register(Rule{
		Name:     "merlin.polling",
		Scenario: "merlin",
		Match: func(f Features) (bool, string) {
			return f.TLSDetected && f.Exchanges >= 2 &&
				f.ExchInterval >= 15 && f.ExchInterval <= 90, ""
		},
	})
}
