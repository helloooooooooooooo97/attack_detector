package rules

import "strings"

func init() {
	Register(Rule{
		Name:     "ksrat.beacon",
		Scenario: "ksrat",
		Match: func(f Features) (bool, string) {
			return !f.TLSDetected &&
				strings.Contains(f.RawClient, "POST /ks/login") &&
				f.Duration < 4 &&
				f.PeerGap >= 12 && f.PeerGap <= 34, ""
		},
	})
}
