package rules

func init() {
	// Yinhu (银狐) trojan family (closed-source, protocol-driven lab):
	// covert UDP channel with periodic fixed-size datagrams (48B), highly
	// regular rhythm; part of a dual UDP + HTTPS C2 channel.
	Register(Rule{
		Name:     "yinhu.udp_beacon",
		Scenario: "yinhu",
		Match: func(f Features) (bool, string) {
			return f.IsUDP && !f.TLSDetected &&
				f.Duration > 30 &&
				f.RawSmallC >= 3 &&
				f.RawIntervalC >= 5 && f.RawIntervalC <= 12 &&
				f.RawCBytes >= 96, ""
		},
	})
}
