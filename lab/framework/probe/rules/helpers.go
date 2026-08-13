package rules

// heartbeat is a generic rule factory for periodic small records/payloads.
//   raw=true  -> use raw TCP payload features (non-TLS protocols)
//   raw=false -> use TLS application-data record features
func heartbeat(name, scenario string, raw bool, minEv, lo, hi float64) Rule {
	return heartbeatOpts(name, scenario, raw, minEv, lo, hi, false)
}

func heartbeatOpts(name, scenario string, raw bool, minEv, lo, hi float64,
	nonTLSOnly bool) Rule {
	return Rule{
		Name:     name,
		Scenario: scenario,
		Match: func(f Features) (bool, string) {
			if nonTLSOnly && f.TLSDetected {
				return false, ""
			}
			var nC, nS int
			var iC, iS float64
			if raw {
				nC, nS = f.RawSmallC, f.RawSmallS
				iC, iS = f.RawIntervalC, f.RawIntervalS
			} else {
				nC, nS = f.SmallC, f.SmallS
				iC, iS = f.IntervalC, f.IntervalS
			}
			return nC >= int(minEv) && nS >= int(minEv) &&
				iC >= lo && iC <= hi && iS >= lo && iS <= hi, ""
		},
	}
}
