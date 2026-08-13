package rules

func init() {
	// Manlinghua (蔓灵花) weapon kit (closed-source, protocol-driven lab):
	// multi-stage campaign. Delivery = HTTP short bursts; persistence =
	// HTTPS long-lived C2 connection with periodic checkins (12s±10%).
	Register(Rule{
		Name:     "manlinghua.c2_phase",
		Scenario: "manlinghua",
		Match: func(f Features) (bool, string) {
			return f.TLSDetected &&
				f.ServerName == "ml-c2.local" &&
				f.Duration > 20 &&
				f.RawIntervalC >= 8 && f.RawIntervalC <= 18 &&
				f.RawCBytes >= 1500, ""
		},
	})
}
