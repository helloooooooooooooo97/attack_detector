package rules

func init() {
	// Meterpreter reverse HTTPS opens a burst of short TLS connections to
	// the handler during session init. The burst aggregation lives in the
	// main emitter (metasploit.meterpreter); this per-flow rule stays as a
	// lightweight complement for long-lived TLS links with periodic comms.
	Register(Rule{
		Name:     "metasploit.meterpreter",
		Scenario: "metasploit",
		Match: func(f Features) (bool, string) {
			return f.TLSDetected && f.Duration >= 20 &&
				f.RawSmallC >= 2 && f.RawSmallS >= 2 &&
				f.RawIntervalC >= 2 && f.RawIntervalC <= 40 &&
				f.RawIntervalS >= 2 && f.RawIntervalS <= 40 &&
				f.RawIntervalC > 0 && f.RawIntervalS > 0 &&
				abs(f.RawIntervalC-f.RawIntervalS) <= 4, ""
		},
	})
}
