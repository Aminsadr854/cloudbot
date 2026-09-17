#!/usr/bin/env python3
import socket, sys, threading, time
PORT = int(sys.argv[1]); BANNER = sys.argv[2] == "banner"
BAN = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n"
def handle(c):
    try:
        if BANNER:
            c.sendall(BAN); c.recv(256)
        n = 0
        while True:
            b = c.recv(1 << 16)
            if not b: break
            n += len(b)
    except Exception:
        pass
    finally:
        c.close()
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", PORT)); s.listen(8)
while True:
    c, _ = s.accept(); threading.Thread(target=handle, args=(c,), daemon=True).start()
