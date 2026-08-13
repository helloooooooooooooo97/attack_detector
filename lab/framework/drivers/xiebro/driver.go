// XiebroC2 TCP listener driver.
//
// Accepts the real XiebroC2 Linux TCP client. The client frames every
// message as [4B little-endian length][AES-128-ECB payload] with the fixed
// key "QWERt_CSDMAHUATE" (16B), sends a ClientInfo MessagePack on connect
// and an identical ClientPing every 15s. The listener does not need to
// reply: the client blocks on its first read and keeps pinging.
package main

import (
	"encoding/binary"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"time"
)

func main() {
	port := flag.String("port", "13000", "listen port")
	seconds := flag.Int("seconds", 80, "run duration (s)")
	flag.Parse()

	ln, err := net.Listen("tcp", ":"+*port)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("xiebro listener on :%s for %ds", *port, *seconds)
	go func() {
		time.Sleep(time.Duration(*seconds) * time.Second)
		os.Exit(0)
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go handle(conn)
	}
}

func handle(conn net.Conn) {
	defer conn.Close()
	var total int
	for {
		lenBuf := make([]byte, 4)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		n := binary.LittleEndian.Uint32(lenBuf)
		if n == 0 || n > 1<<20 {
			return
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		total++
		log.Printf("frame from %s len=%d (ciphertext, AES-ECB)", conn.RemoteAddr(), n)
	}
}
