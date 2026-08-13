package rules

func init() {
	// AntSword PHP webshell (non-TLS HTTP): one short connection per
	// operation, POST body = password param "@eval(@base64_decode(...))" +
	// a random-named param carrying ~1.8KB of base64 PHP code; response is
	// the raw output wrapped in random hex tags.
	Register(Rule{
		Name:     "antsword.php_flow",
		Scenario: "antsword",
		Match: func(f Features) (bool, string) {
			return !f.TLSDetected &&
				f.Duration < 3 &&
				f.FirstC >= 250 && f.FirstC <= 420 &&
				f.RawCBytes >= 1500 && f.RawCBytes <= 3500 &&
				f.RawSBytes >= 200 && f.RawSBytes <= 900, ""
		},
	})
}
