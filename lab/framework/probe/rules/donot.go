package rules

func init() {
	Register(Rule{
		Name:     "donot.c2_phase",
		Scenario: "donot",
		Match: func(f Features) (bool, string) {
			return f.TLSDetected &&
				f.ServerName == "donot-c2.local" &&
				f.Duration > 20 &&
				f.RawIntervalC >= 9 && f.RawIntervalC <= 22 &&
				f.RawCBytes >= 1200, ""
		},
	})
}
