package rules

func init() {
	// TransparentTribe (APT, closed-source, protocol-driven lab): C2 rides
	// a Telegram-style HTTPS API, short GET polling, message-text responses
	// significantly larger than requests.
	Register(Rule{
		Name:     "transparenttribe.poll",
		Scenario: "transparenttribe",
		Match: func(f Features) (bool, string) {
			return f.TLSDetected &&
				f.ServerName == "api.telegramtt.local" &&
				f.Duration < 6 &&
				f.PeerGap >= 7 && f.PeerGap <= 18 &&
				f.RawSBytes > f.RawCBytes, ""
		},
	})
}
