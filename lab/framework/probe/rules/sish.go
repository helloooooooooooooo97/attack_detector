package rules

import "strings"

func init() {
	// sish: SSH-based reverse tunnel. The SSH control connection is
	// long-lived; both peers emit small encrypted keepalive payloads
	// (~28-52B) every few seconds (ServerAliveInterval / server ping).
	// Non-TLS: SSH has its own crypto and no TLS handshake.
	Register(Rule{
		Name:     "sish.ssh_tunnel",
		Scenario: "sish",
		Match: func(f Features) (bool, string) {
			return !f.TLSDetected &&
				strings.Contains(f.RawClient, "SSH-2.0-") &&
				f.RawSmallC >= 3 && f.RawSmallS >= 3 &&
				f.RawIntervalC >= 3 && f.RawIntervalC <= 8 &&
				f.RawIntervalS >= 3 && f.RawIntervalS <= 8, ""
		},
	})
}
