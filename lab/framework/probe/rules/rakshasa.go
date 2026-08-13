package rules

import "strings"

func init() {
	// Rakshasa (closed-source, protocol-driven lab): multi-hop proxy with
	// its own encrypted TCP protocol, fixed frame header (RAKS), periodic
	// keepalive on a long-lived connection.
	Register(Rule{
		Name:     "rakshasa.keepalive",
		Scenario: "rakshasa",
		Match: func(f Features) (bool, string) {
			return !f.TLSDetected && !f.IsUDP &&
				f.Duration > 40 &&
				strings.Contains(f.RawClient, "RAKS") &&
				f.RawSmallC >= 2 &&
				f.RawIntervalC >= 14 && f.RawIntervalC <= 30, ""
		},
	})
}
