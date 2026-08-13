package rules

import "strings"

func init() {
	// natpass (non-TLS TCP): the client opens with a protobuf handshake
	// (~86+ bytes, containing "remote"/"server"), then keeps a periodic
	// keepalive on the long-lived connection.
	Register(Rule{
		Name:     "natpass.handshake",
		Scenario: "natpass",
		Match: func(f Features) (bool, string) {
			return !f.TLSDetected && f.FirstC >= 60 && f.FirstC <= 200 &&
				f.FirstS >= 10 && f.FirstS <= 200 &&
				(strings.Contains(f.RawClient, "remote") ||
					strings.Contains(f.RawClient, "server")), ""
		},
	})
	Register(Rule{
		Name:     "natpass.keepalive",
		Scenario: "natpass",
		Match: func(f Features) (bool, string) {
			return !f.TLSDetected &&
				(strings.Contains(f.RawClient, "remote") ||
					strings.Contains(f.RawClient, "server")) &&
				f.RawSmallC >= 1 && f.RawSmallS >= 1 &&
				f.RawIntervalC >= 2 && f.RawIntervalC <= 120 &&
				f.RawIntervalS >= 2 && f.RawIntervalS <= 120, ""
		},
	})
}
