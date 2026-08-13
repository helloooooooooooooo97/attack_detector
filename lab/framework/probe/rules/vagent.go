package rules

func init() {
	Register(Rule{
		Name:     "vagent.heartbeat",
		Scenario: "vagent",
		Match: func(f Features) (bool, string) {
			return f.TLSDetected &&
				f.ServerName == "vagent-c2.local" &&
				f.Duration > 30 &&
				f.RawIntervalC >= 10 && f.RawIntervalC <= 23 &&
				f.RawCBytes >= 1200, ""
		},
	})
}
