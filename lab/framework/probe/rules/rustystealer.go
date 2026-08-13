package rules

func init() {
	// RustyStealer (Ymir ransomware group, closed-source, protocol-driven
	// lab): HTTPS encrypted exfil bursts, upload-heavy, short flows.
	Register(Rule{
		Name:     "rustystealer.exfil_burst",
		Scenario: "rustystealer",
		Match: func(f Features) (bool, string) {
			return f.TLSDetected &&
				f.ServerName == "c2.rustystealer.local" &&
				f.Duration < 2 &&
				f.ReqBytes >= 2000 && f.ReqBytes > f.RespBytes, ""
		},
	})
}
