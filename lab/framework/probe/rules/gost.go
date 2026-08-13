package rules

import "strings"

func init() {
	// gost relay over websocket: browser-style ping/pong frames keep the
	// connection alive; over raw TCP tunnels the keepalive appears as
	// periodic small payloads. In the lab we relay small beacon-like
	// checkins through the tunnel every 8s.
	Register(Rule{
		Name:     "gost.keepalive",
		Scenario: "gost",
		Match: func(f Features) (bool, string) {
			return !f.TLSDetected &&
				strings.Contains(f.RawClient, "Upgrade: websocket") &&
				f.RawSmallC >= 2 && f.RawSmallS >= 2 &&
				f.RawIntervalC >= 5 && f.RawIntervalC <= 15 &&
				f.RawIntervalS >= 5 && f.RawIntervalS <= 15, ""
		},
	})
}
