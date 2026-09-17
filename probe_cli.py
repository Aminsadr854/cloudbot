#!/usr/bin/env python3
"""Blast data at a sink, optionally after an SSH banner exchange."""
import socket, sys, time
HOST, PORT, MODE, MB = sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4])
BAN = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n"
try:
    c = socket.create_connection((HOST, PORT), timeout=15)
except Exception as e:
    print(f"  {MODE:<7} CONNECT FAILED: {e}"); sys.exit(0)
c.settimeout(25)
try:
    if MODE == "banner":
        c.recv(256)
        c.sendall(BAN)
except Exception as e:
    print(f"  {MODE:<7} BANNER FAILED: {e}"); sys.exit(0)
buf = bytes(1 << 16)
sent = 0; target = MB << 20; t0 = time.time()
try:
    while sent < target and time.time() - t0 < 20:
        c.sendall(buf); sent += len(buf)
except Exception:
    pass
dt = time.time() - t0
print(f"  {MODE:<7} {sent/1e6:7.1f} MB in {dt:5.1f}s = {sent*8/1e6/max(dt,.001):8.2f} Mbps")
c.close()
