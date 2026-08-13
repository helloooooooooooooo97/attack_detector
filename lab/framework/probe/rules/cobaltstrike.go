package rules

func init() {
	// Cobalt Strike beacon (default HTTP profile, replicated byte-for-byte by
	// the geacon Go implementation): each check-in is a short HTTP GET to a
	// profile URI carrying the RSA-encrypted session metadata in a very long
	// Cookie header (~400B), answered by a small fixed-size encrypted body.
	// The beacon polls at a fixed interval (default 60s, geacon 3s here).
	Register(Rule{
		Name:     "cobaltstrike.beacon_checkin",
		Scenario: "cobaltstrike",
		Match: func(f Features) (bool, string) {
			return !f.TLSDetected && f.HasLongCookie &&
				f.Duration < 8 &&
				f.RawCBytes >= 400 && f.RawCBytes <= 1000 &&
				f.RawSBytes >= 80 && f.RawSBytes <= 600, ""
		},
	})
}
