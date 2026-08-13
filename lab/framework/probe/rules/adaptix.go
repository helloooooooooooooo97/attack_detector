package rules

import "strings"

func init() {
	// AdaptixC2 BeaconHTTP (server verified in lab; agent Windows-only,
	// protocol-driven): non-TLS HTTP single-endpoint short flows,
	// POST /checkin with RC4-encrypted base64 payload, periodic checkin.
	Register(Rule{
		Name:     "adaptix.checkin",
		Scenario: "adaptix",
		Match: func(f Features) (bool, string) {
			return !f.TLSDetected &&
				strings.Contains(f.RawClient, "POST /checkin") &&
				f.Duration < 4 &&
				f.PeerGap >= 4 && f.PeerGap <= 16 &&
				f.RawCBytes >= 300 && f.RawCBytes <= 2500, ""
		},
	})
}
