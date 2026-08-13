// DeimosC2 TCP listener driver.
//
// Speaks the real DeimosC2 agent protocol against the real Deimos TCP agent:
//   1. 8-byte big-endian length prefix
//   2. RSA-OAEP(SHA-512) block (256B for 2048-bit key):
//      [1B msgType][32B agentKey][32B session AES-256 key]
//   3. AES-256-CBC (random IV, PKCS7) payload
// Init (type 0) => reply with a generated 32-hex agent key.
// Check-in (type 2) => reply with an empty job list "[]".
//
// The crypto package is copied verbatim from DeimosC2 (MIT):
// github.com/DeimosC2/DeimosC2/lib/crypto
package main

import (
	"crypto/rsa"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"tflab/deimos-driver/crypto"
)

var privPEM string

func main() {
	privPath := flag.String("key", "keys/priv.pem", "RSA private key PEM")
	port := flag.String("port", "14000", "listen port")
	seconds := flag.Int("seconds", 70, "run duration (s)")
	flag.Parse()

	pem, err := os.ReadFile(*privPath)
	if err != nil {
		log.Fatalf("read key: %v", err)
	}
	priv := crypto.BytesToPrivateKey(pem)

	ln, err := net.Listen("tcp", ":"+*port)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("deimos listener on :%s for %ds", *port, *seconds)
	go func() {
		time.Sleep(time.Duration(*seconds) * time.Second)
		os.Exit(0)
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			return
		}
		go handle(conn, priv)
	}
}

func handle(conn net.Conn, priv *rsa.PrivateKey) {
	defer conn.Close()
	rawLen := make([]byte, 8)
	if _, err := io.ReadFull(conn, rawLen); err != nil {
		return
	}
	msgLen := binary.BigEndian.Uint64(rawLen)
	if msgLen < 256 || msgLen > 1<<20 {
		log.Printf("bad message length %d", msgLen)
		return
	}
	message := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, message); err != nil {
		return
	}

	decRSA := crypto.DecryptWithPrivateKey(message[0:256], priv)
	msgType := string(decRSA[0])
	aesKey := decRSA[37:]
	payload := crypto.Decrypt(message[256:], aesKey)

	var reply []byte
	switch msgType {
	case "0": // agent registration
		name := agentName(payload)
		log.Printf("init from %s agentKey=%s", conn.RemoteAddr(), name)
		reply = []byte(name)
	case "2": // periodic check-in
		log.Printf("check-in from %s data=%q", conn.RemoteAddr(), string(payload))
		reply = []byte("[]")
	default:
		log.Printf("unknown msgType %q", msgType)
		return
	}
	sendMsg(conn, reply, aesKey)
}

// agentName mirrors DeimosC2's AgentKey(): 36 lowercase hex chars.
func agentName(payload []byte) string {
	s := fmt.Sprintf("%x", payload)
	if len(s) < 36 {
		s = strings.Repeat("0", 36-len(s)) + s
	}
	return s[:36]
}

// sendMsg: 8B BE length + AES-256-CBC(payload, session key).
func sendMsg(conn net.Conn, data []byte, aesKey []byte) {
	enc := crypto.Encrypt(data, aesKey)
	buf := make([]byte, 8+len(enc))
	binary.BigEndian.PutUint64(buf, uint64(len(enc)))
	copy(buf[8:], enc)
	_, _ = conn.Write(buf)
}
