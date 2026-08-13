package rules

import "strings"

func init() {
	Register(Rule{
		Name:     "sparkrat.beacon",
		Scenario: "sparkrat",
		Match: func(f Features) (bool, string) {
			return !f.TLSDetected &&
				strings.Contains(f.RawClient, "POST /spark/check") &&
				f.Duration < 4 &&
				f.PeerGap >= 6 && f.PeerGap <= 17, ""
		},
	})
}
