package rules

import "strings"

func init() {
	Register(Rule{
		Name:     "wmrat.beacon",
		Scenario: "wmrat",
		Match: func(f Features) (bool, string) {
			return !f.TLSDetected &&
				strings.Contains(f.RawClient, "POST /wm/update") &&
				f.Duration < 4 &&
				f.PeerGap >= 7 && f.PeerGap <= 20, ""
		},
	})
}
