package rules

import "strings"

func init() {
	// Vshell (discontinued red-team RAT, protocol-driven lab): long-lived
	// TCP channel, fixed 10s heartbeat, small frames carrying arch/IP
	// declarations with VKey auth (frame magic VSHL).
	Register(Rule{
		Name:     "vshell.heartbeat",
		Scenario: "vshell",
		Match: func(f Features) (bool, string) {
			return !f.TLSDetected && !f.IsUDP &&
				f.Duration > 30 &&
				strings.Contains(f.RawClient, "VSHL") &&
				f.RawSmallC >= 4 &&
				f.RawIntervalC >= 7 && f.RawIntervalC <= 14, ""
		},
	})
}
