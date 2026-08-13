package rules

func init() {
	Register(Rule{
		Name:     "sidewinder.c2_phase",
		Scenario: "sidewinder",
		Match: func(f Features) (bool, string) {
			return f.TLSDetected &&
				f.ServerName == "sidewinder-c2.local" &&
				f.Duration > 20 &&
				f.RawIntervalC >= 7 && f.RawIntervalC <= 20 &&
				f.RawCBytes >= 1200, ""
		},
	})
}
