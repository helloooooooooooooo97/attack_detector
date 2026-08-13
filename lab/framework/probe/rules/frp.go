package rules

func init() {
	// frp (TLS mode): frpc sends a heartbeat to frps every 30s by default
	// (transport.heartbeatInterval), visible as periodic small TLS records.
	Register(heartbeat("frp.heartbeat", "frp", false, 1, 20, 45))
}
