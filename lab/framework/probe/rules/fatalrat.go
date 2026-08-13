package rules

import "strings"

func init() {
	Register(Rule{
		Name:     "fatalrat.beacon",
		Scenario: "fatalrat",
		Match: func(f Features) (bool, string) {
			return !f.TLSDetected &&
				strings.Contains(f.RawClient, "POST /fatal/check") &&
				f.Duration < 4 &&
				f.PeerGap >= 7 && f.PeerGap <= 20, ""
		},
	})
}
