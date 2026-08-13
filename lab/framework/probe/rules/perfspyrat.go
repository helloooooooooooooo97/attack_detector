package rules

import "strings"

func init() {
	Register(Rule{
		Name:     "perfspyrat.beacon",
		Scenario: "perfspyrat",
		Match: func(f Features) (bool, string) {
			return !f.TLSDetected &&
				strings.Contains(f.RawClient, "POST /perf/report") &&
				f.Duration < 4 &&
				f.PeerGap >= 6 && f.PeerGap <= 17, ""
		},
	})
}
