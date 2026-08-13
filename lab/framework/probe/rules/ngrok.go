package rules

func init() {
	// Ngrok agent TLS: the client always dials connect.ngrok-agent.com:443
	// with TLS1.3. The fixed SNI is the stable, tool-specific fingerprint
	// (the agent does not randomize it).
	Register(Rule{
		Name:     "ngrok.agent_tls",
		Scenario: "ngrok",
		Match: func(f Features) (bool, string) {
			return f.TLSDetected && f.ServerName == "connect.ngrok-agent.com", ""
		},
	})
}
