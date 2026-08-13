#!/bin/bash
# Brute-force behavior scenario: one source opens many short TCP connections
# to the same dst port rapidly (SSH-login-style attempts).
set +e
OUT="${OUT:-/lab/src/out}"
mkdir -p "$OUT"

python3 - <<'PY' > "$OUT/bf_drv.log" 2>&1
import socket, threading, time

def server():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 2222))
    s.listen(128)
    end = time.time() + 30
    while time.time() < end:
        try:
            s.settimeout(1)
            c, _ = s.accept()
        except socket.timeout:
            continue
        try:
            c.sendall(b"SSH-2.0-OpenSSH_8.9p1\r\n")
            c.recv(256)
        except OSError:
            pass
        c.close()

t = threading.Thread(target=server, daemon=True)
t.start()
time.sleep(0.5)

# 80 attempts in ~8s (10/s) from one source to the same port
for i in range(80):
    try:
        c = socket.create_connection(("127.0.0.1", 2222), timeout=3)
        c.recv(256)
        c.sendall(b"SSH-2.0-libssh_0.9.6\r\n" + bytes(48))
        c.close()
    except OSError as e:
        print("attempt", i, "fail", e)
    time.sleep(0.1)
time.sleep(3)
print("bruteforce driver done: 80 attempts")
PY
RC=$?
echo "bruteforce scenario rc=$RC" >> "$OUT/bruteforce.log"
exit 0
