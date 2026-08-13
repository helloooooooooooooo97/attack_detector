package rules

import "strings"

func init() {
	Register(Rule{
		Name:     "octopus.beacon",
		Scenario: "octopus",
		Match: func(f Features) (bool, string) {
			return !f.TLSDetected &&
				strings.Contains(f.RawClient, "POST /api/v1/beacon") &&
				f.Duration < 4 &&
				f.PeerGap >= 9 && f.PeerGap <= 25, ""
		},
	})
}
