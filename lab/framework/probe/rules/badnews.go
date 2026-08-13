package rules

import "strings"

func init() {
	Register(Rule{
		Name:     "badnews.beacon",
		Scenario: "badnews",
		Match: func(f Features) (bool, string) {
			return !f.TLSDetected &&
				strings.Contains(f.RawClient, "POST /news/check") &&
				f.Duration < 4 &&
				f.PeerGap >= 12 && f.PeerGap <= 34, ""
		},
	})
}
