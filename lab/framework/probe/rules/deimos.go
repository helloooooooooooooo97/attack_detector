package rules

func init() {
	// DeimosC2 TCP agent (non-TLS): every message is
	//   [8B big-endian length][256B RSA-OAEP block][AES-256-CBC payload]
	// so the first client payload is always 8 + 256 + 16*(k+1) bytes, i.e.
	// ≡ 8 (mod 16). The server reply is [8B length][AES payload] and the
	// agent dials a fresh short-lived connection for each check-in.
	Register(Rule{
		Name:     "deimos.checkin",
		Scenario: "deimos",
		Match: func(f Features) (bool, string) {
			return !f.TLSDetected &&
				f.Duration < 5 &&
				f.FirstC >= 280 && f.FirstC <= 640 && f.FirstC%16 == 8 &&
				f.FirstS >= 32 && f.FirstS <= 128 && f.FirstS%16 == 8, ""
		},
	})
}
