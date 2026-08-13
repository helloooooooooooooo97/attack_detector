package rules

func init() {
	// SILENTTRINITY (Python server + PowerShell agent, protocol-driven lab):
	// gRPC/HTTP2 + mTLS observable as a long TLS connection with periodic
	// bidirectional exchanges; fixed SNI + steady checkin rhythm.
	Register(Rule{
		Name:     "silenttrinity.checkin",
		Scenario: "silenttrinity",
		Match: func(f Features) (bool, string) {
			return f.TLSDetected &&
				f.ServerName == "st-grpc.local" &&
				f.Duration > 30 &&
				f.Exchanges >= 3 &&
				f.ExchInterval >= 10 && f.ExchInterval <= 40, ""
		},
	})
}
