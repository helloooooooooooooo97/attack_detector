package rules

func init() {
	// Sliver (mTLS beacon): the implant checks in on a fixed interval
	// (default 30s) plus jitter; each checkin is one HTTP/TLS exchange.
	Register(Rule{
		Name:     "sliver.beacon",
		Scenario: "sliver",
		Match: func(f Features) (bool, string) {
			// mTLS beacons appear as periodic ~29B TLS records (~30s default)
			return f.TLSDetected && f.SmallC >= 2 && f.SmallS >= 2 &&
				f.IntervalC >= 20 && f.IntervalC <= 60 &&
				f.IntervalS >= 20 && f.IntervalS <= 60, ""
		},
	})
}
