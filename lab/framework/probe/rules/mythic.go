package rules

func init() {
	// Mythic C2 (http profile, Athena-style agent): the agent keeps a
	// persistent HTTP connection, sending periodic
	//   GET /index?q=<long base64>   (~390B)
	// and occasional
	//   POST /data                   (~2.7KB encrypted body)
	// The server replies 200 with Cache-Control: max-age=0, no-cache and a
	// stable-size JSON body; check-in cadence is ~10s with jitter.
	Register(Rule{
		Name:     "mythic.http_checkin",
		Scenario: "mythic",
		Match: func(f Features) (bool, string) {
			return !f.TLSDetected && f.HasC2QueryParam &&
				f.Duration > 15 &&
				f.RawSmallC >= 2 &&
				f.RawIntervalC >= 5 && f.RawIntervalC <= 25 &&
				f.RawCBytes >= 2000 && f.RawCBytes <= 20000 &&
				f.RawSBytes >= 1000 && f.RawSBytes <= 10000, ""
		},
	})
}
