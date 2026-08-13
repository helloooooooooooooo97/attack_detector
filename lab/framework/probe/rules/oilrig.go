package rules

import "strings"

func init() {
	Register(Rule{
		Name:     "oilrig.beacon",
		Scenario: "oilrig",
		Match: func(f Features) (bool, string) {
			return !f.TLSDetected &&
				strings.Contains(f.RawClient, "POST /ps/run") &&
				f.Duration < 4 &&
				f.PeerGap >= 10 && f.PeerGap <= 30, ""
		},
	})
}
