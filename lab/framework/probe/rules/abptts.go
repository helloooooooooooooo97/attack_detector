package rules

func init() {
	// ABPTTS (non-TLS HTTP): TCP tunneled over one-shot POSTs to a JSP
	// endpoint. Each connection carries exactly one POST with a custom
	// access-key header and an AES-CBC encrypted parameter; the response is
	// wrapped in a fake "System Status API" HTML prefix/suffix. Request
	// ~500-800B, response ~280-600B, many short flows in a row.
	Register(Rule{
		Name:     "abptts.tunnel_post",
		Scenario: "abptts",
		Match: func(f Features) (bool, string) {
			return !f.TLSDetected &&
				f.Duration < 3 &&
				f.FirstC >= 300 && f.FirstC <= 700 &&
				f.RawCBytes >= 450 && f.RawCBytes <= 950 &&
				f.RawSBytes >= 250 && f.RawSBytes <= 800, ""
		},
	})
}
