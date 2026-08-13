package rules

import "strings"

func init() {
	Register(Rule{
		Name:     "loki.beacon",
		Scenario: "loki",
		Match: func(f Features) (bool, string) {
			return !f.TLSDetected &&
				strings.Contains(f.RawClient, "POST /loki/status") &&
				f.Duration < 4 &&
				f.PeerGap >= 9 && f.PeerGap <= 25, ""
		},
	})
}
