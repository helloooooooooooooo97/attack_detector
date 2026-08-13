package rules

import "strings"

func init() {
	// Remcos (closed-source, protocol-driven lab): long-lived TCP channel,
	// fixed frame magic (REMC) + encrypted frames, periodic heartbeat.
	Register(Rule{
		Name:     "remcos.heartbeat",
		Scenario: "remcos",
		Match: func(f Features) (bool, string) {
			return !f.TLSDetected && !f.IsUDP &&
				f.Duration > 30 &&
				strings.Contains(f.RawClient, "REMC") &&
				f.RawSmallC >= 3 &&
				f.RawIntervalC >= 8 && f.RawIntervalC <= 18, ""
		},
	})
}
