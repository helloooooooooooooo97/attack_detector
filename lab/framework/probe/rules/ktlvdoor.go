package rules

import "strings"

func init() {
	// KTLVdoor (closed-source, protocol-driven lab): long-lived TCP with a
	// fixed frame header (KTLV) + custom encryption, periodic heartbeat.
	Register(Rule{
		Name:     "ktlvdoor.heartbeat",
		Scenario: "ktlvdoor",
		Match: func(f Features) (bool, string) {
			return !f.TLSDetected && !f.IsUDP &&
				f.Duration > 30 &&
				strings.Contains(f.RawClient, "KTLV") &&
				f.RawSmallC >= 2 &&
				f.RawIntervalC >= 10 && f.RawIntervalC <= 22, ""
		},
	})
}
