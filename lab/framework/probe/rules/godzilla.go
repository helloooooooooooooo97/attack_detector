package rules

func init() {
	// Godzilla PHP webshell (non-TLS HTTP). Each operation is one short
	// connection with a single request/response:
	//   - session bootstrap: a huge POST (payload.php, ~50KB)
	//   - method calls: ~400B POST (XOR+base64) -> ~1.1-1.5KB response
	// Request body is "pass=<urlencoded base64(XOR data)>" and the response
	// is wrapped in md5(pass+key) markers.
	Register(Rule{
		Name:     "godzilla.payload_upload",
		Scenario: "godzilla",
		Match: func(f Features) (bool, string) {
			return !f.TLSDetected &&
				f.Duration < 3 &&
				f.FirstC >= 300 && f.FirstC <= 700 &&
				f.RawCBytes >= 40000 && f.RawCBytes <= 90000 &&
				f.RawSBytes >= 100 && f.RawSBytes <= 2000, ""
		},
	})
	Register(Rule{
		Name:     "godzilla.php_flow",
		Scenario: "godzilla",
		Match: func(f Features) (bool, string) {
			return !f.TLSDetected &&
				f.Duration < 3 &&
				f.FirstC >= 300 && f.FirstC <= 700 &&
				f.FirstS >= 300 && f.FirstS <= 1500 &&
				f.RawCBytes >= 300 && f.RawCBytes <= 1000 &&
				f.RawSBytes >= 800 && f.RawSBytes <= 4000, ""
		},
	})
}
