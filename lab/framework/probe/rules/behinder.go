package rules

func init() {
	Register(Rule{
		Name:     "behinder.mem_shell_flow",
		Scenario: "behinder",
		Match: func(f Features) (bool, string) {
			return r1MemShell(f), ""
		},
	})
	Register(Rule{
		Name:     "behinder.file_webshell_flow",
		Scenario: "behinder",
		Match: func(f Features) (bool, string) {
			return r2FileShell(f), ""
		},
	})
}

// r1MemShell: memory-shell pattern - short flows, one exchange, ~13 TLS
// records, big request chunks, request dominates response.
func r1MemShell(f Features) bool {
	return f.Exchanges == 1 &&
		f.Records >= 10 && f.Records <= 16 &&
		f.BigReq >= 1 &&
		f.ReqBytes > f.RespBytes &&
		f.Duration < 2.5
}

// r2FileShell: file-webshell pattern - long-lived reuse flow with constant
// 8225B request chunks.
func r2FileShell(f Features) bool {
	return f.Exchanges >= 5 &&
		f.Records >= 40 &&
		f.Chunks8225 >= 5 &&
		f.ReqBytes > f.RespBytes
}
