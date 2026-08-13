// Minimal Cobalt Strike teamserver emulator for the lab.
//
// Speaks the CS 4.x default HTTP profile against the real beacon protocol
// implementation (geacon, a Go re-implementation of the CS beacon wire
// protocol):
//
//   beacon -> server: GET /load with Cookie: <base64 RSA-encrypted metadata>
//       metadata = [16B session AES key seed][2B ANSI][2B OEM][agent info]
//       AES key / HMAC key = sha256(seed)[:16] / sha256(seed)[16:32]
//   server -> beacon: [4B BE length][AES-CBC(counter+tasking, key,
//       IV="abcdefghijklmnop")][HMAC-SHA256(cipher, key)[:16]]
//   beacon -> server: POST /submit.php?id=<id> with encrypted result packets
//
// The emulator only ever sends an empty tasking list, so the beacon keeps
// polling every WaitTime seconds.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
)

var iv = []byte("abcdefghijklmnop")

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "listen address")
	keyPath := flag.String("key", "keys/priv.pem", "RSA private key PEM")
	flag.Parse()

	pemBytes, err := os.ReadFile(*keyPath)
	if err != nil {
		log.Fatalf("read key: %v", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		log.Fatalf("bad key pem")
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("parse key: %v", err)
	}
	rsaKey := priv.(*rsa.PrivateKey)

	http.HandleFunc("/load", func(w http.ResponseWriter, r *http.Request) {
		cookie := r.Header.Get("Cookie")
		if cookie == "" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		raw, err := base64.StdEncoding.DecodeString(cookie)
		if err != nil {
			log.Printf("bad metadata b64: %v", err)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		meta, err := rsa.DecryptPKCS1v15(rand.Reader, rsaKey, raw)
		if err != nil || len(meta) < 20 {
			log.Printf("rsa decrypt failed: %v (len=%d)", err, len(raw))
			w.WriteHeader(http.StatusNotFound)
			return
		}
		// metadata layout: [4B magic][4B length][16B session key seed]...
		if len(meta) < 24 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		seed := meta[8:24]
		sh := sha256.Sum256(seed)
		aesKey := sh[:16]
		hmacKey := sh[16:32]
		log.Printf("beacon checkin from %s meta_len=%d", r.RemoteAddr, len(meta))
		writeTasking(w, aesKey, hmacKey)
	})

	http.HandleFunc("/submit.php", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		log.Printf("result POST from %s id=%s len=%d", r.RemoteAddr, r.URL.Query().Get("id"), len(body))
		w.WriteHeader(http.StatusOK)
	})

	log.Printf("fake CS teamserver on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, nil))
}

// writeTasking replies with an empty tasking packet:
// [4B length][AES-CBC(counter + 0-len tasking)][16B HMAC].
func writeTasking(w http.ResponseWriter, aesKey, hmacKey []byte) {
	plain := make([]byte, 8)
	binary.BigEndian.PutUint32(plain, 1) // counter
	binary.BigEndian.PutUint32(plain[4:], 0)
	// 'A' padding to a 16-byte block (same as the beacon's PaddingWithA)
	for len(plain)%16 != 0 {
		plain = append(plain, 'A')
	}
	block, _ := aes.NewCipher(aesKey)
	ct := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, plain)

	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(ct)
	sum := mac.Sum(nil)[:16]

	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(ct)
	_, _ = w.Write(sum)
}
