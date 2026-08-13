package rules

func init() {
	// OceanLotus (APT, closed-source, protocol-driven lab): HTTPS periodic
	// C2 return with fixed SNI/UA; encrypted payloads, request > response.
	Register(Rule{
		Name:     "oceanlotus.beacon",
		Scenario: "oceanlotus",
		Match: func(f Features) (bool, string) {
			return f.TLSDetected &&
				f.ServerName == "cdn.oceanlotus.local" &&
				f.Duration < 6 &&
				f.PeerGap >= 12 && f.PeerGap <= 40 &&
				f.ReqBytes >= 600 && f.ReqBytes > f.RespBytes-200, ""
		},
	})
}
