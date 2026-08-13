package rules

func init() {
	// Covenant C2 (non-TLS HTTP listener): the grunt POSTs to "profile"
	// URLs with a fixed request format
	//   i=<32 hex>&data=<base64 JSON {GUID,Type,IV,EncryptedMessage,HMAC}>
	// and an ASPSESSIONID cookie; check-ins repeat at the configured delay.
	Register(Rule{
		Name:     "covenant.http_profile",
		Scenario: "covenant",
		Match: func(f Features) (bool, string) {
			return !f.TLSDetected && f.HasProfilePost &&
				f.Duration < 30 &&
				f.RawCBytes >= 500 && f.RawCBytes <= 4000 &&
				f.RawSBytes >= 100 && f.RawSBytes <= 2500, ""
		},
	})
}
