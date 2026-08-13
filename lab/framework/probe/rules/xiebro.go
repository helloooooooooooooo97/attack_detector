package rules

func init() {
	// XiebroC2 Linux TCP client (non-TLS): one long-lived connection,
	// ClientInfo on connect, then an identical AES-128-ECB(ClientPing)
	// MessagePack every 15s: [4B LE length][~48B ciphertext]. The server
	// never replies, so client->server is the only direction.
	Register(Rule{
		Name:     "xiebro.heartbeat",
		Scenario: "xiebro",
		Match: func(f Features) (bool, string) {
			return !f.TLSDetected &&
				f.Duration > 30 &&
				f.RawSmallC >= 2 &&
				f.RawSmallS == 0 &&
				f.RawIntervalC >= 12 && f.RawIntervalC <= 18, ""
		},
	})
}
