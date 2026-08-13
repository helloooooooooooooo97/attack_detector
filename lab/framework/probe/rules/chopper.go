package rules

func init() {
	// China Chopper (菜刀) one-line webshell, non-TLS HTTP. Classic
	// client opens one short connection per operation:
	//   POST shell.php  body: z0=<base64 PHP eval payload>&z1=<arg>
	// Request is 300-2500B, response carries plaintext output. No
	// keep-alive, no heartbeat, request > response for file reads.
	Register(Rule{
		Name:     "chopper.eval_flow",
		Scenario: "chopper",
		Match: func(f Features) (bool, string) {
			return !f.TLSDetected &&
				f.Duration < 4 &&
				f.FirstC >= 200 && f.FirstC <= 4000 &&
				f.RawCBytes >= 200 && f.RawCBytes <= 6000 &&
				f.RawSBytes >= 30 && f.RawSBytes <= 30000 &&
				f.HasChopperParam, ""
		},
	})
}
