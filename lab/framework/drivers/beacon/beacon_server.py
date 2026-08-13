#!/usr/bin/env python3
"""Local lab C2 endpoint for beacon_agent.py (HTTP / HTTPS / raw TCP).

Usage:
  beacon_server.py --transport http|https|tcp --port N
                   [--cert cert.pem --key key.pem]   # https
"""

import argparse
import hashlib
import random
import socket
import socketserver
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def resp_bytes(seed, size):
    out = b""
    i = 0
    while len(out) < size:
        out += hashlib.sha256(f"{seed}:{i}".encode()).digest()
        i += 1
    return out[:size]


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _respond(self):
        size = random.randint(200, 600)
        body = resp_bytes("server", size)
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        self._respond()

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        self._respond()

    def log_message(self, *args):  # silence
        pass


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        # long-lived stream: keep answering frames until the client closes
        while True:
            try:
                data = self.request.recv(65535)
                if not data:
                    break
                self.request.sendall(resp_bytes("tcp", 200))
            except OSError:
                break


class UDPServer:
    def __init__(self, port, resp_size=200):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", port))
        self.resp_size = resp_size

    def serve_forever(self):
        while True:
            data, addr = self.sock.recvfrom(65535)
            if data:
                self.sock.sendto(resp_bytes("udp", self.resp_size), addr)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--transport", default="http")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--cert")
    ap.add_argument("--key")
    args = ap.parse_args()

    if args.transport == "udp":
        srv = UDPServer(args.port)
        print(f"server udp on :{args.port}", flush=True)
        srv.serve_forever()
    elif args.transport == "tcp":
        srv = socketserver.ThreadingTCPServer(("127.0.0.1", args.port), TCPHandler)
        srv.serve_forever()
    else:
        httpd = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
        if args.transport == "https":
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(args.cert, args.key)
            httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        print(f"server {args.transport} on :{args.port}", flush=True)
        httpd.serve_forever()


if __name__ == "__main__":
    main()
