package rules

import "strings"

func init() {
	// TriStealer (closed-source, protocol-driven lab): short HTTP POST
	// bursts exfiltrating stolen data; upload >> download, no heartbeat.
	Register(Rule{
		Name:     "tristealer.exfil_burst",
		Scenario: "tristealer",
		Match: func(f Features) (bool, string) {
			return !f.TLSDetected &&
				strings.Contains(f.RawClient, "POST /upload") &&
				f.Duration < 2 &&
				f.RawCBytes >= 2000 && f.RawCBytes > f.RawSBytes, ""
		},
	})
}
