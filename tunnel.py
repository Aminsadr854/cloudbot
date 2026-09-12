"""
Build and tear down tunnels between an Iran server and a foreign server, and
plain port forwards - the things that were being done by hand until now.

Reaching the Iran side is the hard part: many Iran servers refuse SSH from
abroad, so an Iran jump host (one that DOES answer from abroad) is used, and
the connection to the real target is tunnelled through it - Iran-to-Iran,
which always works. The foreign side is reached directly.

Two tunnel types, chosen by the caller because which one survives depends on
the path:
  gre     kernel GRE (protocol 47). Zero CPU and carries UDP, but some Iran
          routes drop protocol 47 outright.
  paytun  the userspace TCP relay. Works wherever plain TCP does - which is
          almost everywhere - but is TCP only.
"""
import asyncio
import json

import asyncssh

PAYTUN_BIN = "/opt/cloudbot/assets/paytun"  # uploaded once, shipped to targets


async def connect(host, port, user, password, jump=None):
    """
    SSH to a host. If `jump` is given and the direct connection fails, retry
    through the jump (Iran target reached via the Iran jump, domestically).
    """
    kw = dict(username=user, password=password, known_hosts=None, connect_timeout=20)
    try:
        return await asyncio.wait_for(asyncssh.connect(host, port=port, **kw), 25)
    except Exception:
        if not jump:
            raise
        j = await asyncio.wait_for(asyncssh.connect(
            jump["host"], port=int(jump.get("port", 22)), username=jump["user"],
            password=jump["password"], known_hosts=None, connect_timeout=20), 25)
        return await asyncio.wait_for(
            asyncssh.connect(host, port=port, tunnel=j, **kw), 30)


async def run(conn, cmd, timeout=180):
    r = await asyncio.wait_for(conn.run(cmd, check=False), timeout=timeout)
    return r.exit_status, (r.stdout or "") + (r.stderr or "")


# --------------------------------------------------------------------------
# GRE
# --------------------------------------------------------------------------
def _gre_iran_script(dev, subnet_n, foreign_ip, iran_ip, ports):
    dnat = "\n".join(
        f'  nft add rule ip cbtun pre {proto} dport {p} counter dnat to 10.21.{subnet_n}.2 2>/dev/null'
        for p in ports for proto in ("tcp", "udp"))
    return f"""set -e
modprobe ip_gre 2>/dev/null || true
ip link del {dev} 2>/dev/null || true
ip tunnel add {dev} mode gre local {iran_ip} remote {foreign_ip} ttl 255
ip addr add 10.21.{subnet_n}.1/30 dev {dev}
ip link set {dev} mtu 1476 up
sysctl -qw net.ipv4.ip_forward=1
sysctl -qw net.ipv4.conf.all.rp_filter=2 2>/dev/null || true
nft list table ip cbtun >/dev/null 2>&1 && nft delete table ip cbtun
nft add table ip cbtun
nft add chain ip cbtun pre '{{ type nat hook prerouting priority dstnat; }}'
nft add chain ip cbtun post '{{ type nat hook postrouting priority srcnat; }}'
nft add chain ip cbtun forward '{{ type filter hook forward priority 0; policy accept; }}'
nft add rule ip cbtun forward tcp flags syn tcp option maxseg size set 1360
{dnat}
nft add rule ip cbtun post oifname "{dev}" counter masquerade
echo GRE_IRAN_OK
"""


def _gre_foreign_script(dev, subnet_n, foreign_ip, iran_ip):
    return f"""set -e
modprobe ip_gre 2>/dev/null || true
# Clear our own leftovers first. The kernel keys a GRE tunnel on its
# local/remote pair, not on its name, so one stale device - under any name -
# makes every `ip tunnel add` for the same pair fail with EEXIST for good.
# The @NONE suffix that `ip -o link show` prints has to come off, or the
# delete silently does nothing.
for d in $(ip -o link show 2>/dev/null | awk -F': ' '{{print $2}}' | cut -d@ -f1 | grep -E '^cbgre'); do
  ip link del "$d" 2>/dev/null || true
done
ip link del {dev} 2>/dev/null || true
ip tunnel add {dev} mode gre local {foreign_ip} remote {iran_ip} ttl 255
ip addr add 10.21.{subnet_n}.2/30 dev {dev}
ip link set {dev} mtu 1476 up
sysctl -qw net.ipv4.ip_forward=1
sysctl -qw net.ipv4.conf.all.rp_filter=2 2>/dev/null || true
echo GRE_FOREIGN_OK
"""


async def build_gre(iran, foreign, ports, jump, subnet_n, log):
    dev = f"cbgre{subnet_n}"
    await log("اتصال به سرور خارج…")
    fc = await connect(foreign["host"], foreign["port"], foreign["user"], foreign["password"])
    await log("اتصال به سرور ایران (از طریق واسط در صورت نیاز)…")
    ic = await connect(iran["host"], iran["port"], iran["user"], iran["password"], jump=jump)
    try:
        await log("برپاسازی GRE روی سرور خارج…")
        code, out = await run(fc, _gre_foreign_script(dev, subnet_n, foreign["host"], iran["host"]))
        if "GRE_FOREIGN_OK" not in out:
            raise RuntimeError(f"foreign GRE failed: {out[-300:]}")
        await log("برپاسازی GRE روی سرور ایران + فوروارد پورت‌ها…")
        code, out = await run(ic, _gre_iran_script(dev, subnet_n, foreign["host"], iran["host"], ports))
        if "GRE_IRAN_OK" not in out:
            raise RuntimeError(f"iran GRE failed: {out[-300:]}")
        await log("تست تونل…")
        code, out = await run(ic, f"ping -c3 -W2 -q 10.21.{subnet_n}.2 | tail -2")
        return {"dev": dev, "subnet_n": subnet_n, "ping": out.strip()}
    finally:
        fc.close(); ic.close()


async def teardown_gre(iran, foreign, detail, jump, log):
    dev = detail["dev"]
    await log("حذف GRE از سرور خارج…")
    try:
        fc = await connect(foreign["host"], foreign["port"], foreign["user"], foreign["password"])
        await run(fc, f"ip link del {dev} 2>/dev/null; true"); fc.close()
    except Exception as e:
        await log(f"⚠️ خارج: {str(e)[:120]}")
    await log("حذف GRE + قواعد از سرور ایران…")
    try:
        ic = await connect(iran["host"], iran["port"], iran["user"], iran["password"], jump=jump)
        await run(ic, f"ip link del {dev} 2>/dev/null; "
                      f"nft delete table ip cbtun 2>/dev/null; true"); ic.close()
    except Exception as e:
        await log(f"⚠️ ایران: {str(e)[:120]}")


# --------------------------------------------------------------------------
# paytun
# --------------------------------------------------------------------------
async def _ship_paytun(conn):
    """
    Put the current paytun binary on the target, replacing an older build.

    This used to skip the copy whenever any paytun was present, which meant a
    relay built before an upgrade kept the old binary for ever - including the
    build without the SSH greeting, which the Iran-UK shaper holds to 0.14
    Mbit. Comparing digests costs one command and makes upgrades actually land.
    """
    import hashlib
    with open(PAYTUN_BIN, "rb") as f:
        want = hashlib.sha256(f.read()).hexdigest()
    _code, out = await run(
        conn, "sha256sum /usr/local/bin/paytun 2>/dev/null | cut -d' ' -f1")
    if out.strip() == want:
        return
    # Stop first: a running binary cannot be overwritten ("text file busy").
    await run(conn, "systemctl stop paytun-client paytun-server 2>/dev/null; true")
    async with conn.start_sftp_client() as sftp:
        await sftp.put(PAYTUN_BIN, "/usr/local/bin/paytun")
    await run(conn, "chmod +x /usr/local/bin/paytun")


async def build_paytun(iran, foreign, ports, jump, psk, port, log, camo=False):
    """
    Build a paytun pair.

    `camo` adds the SSH greeting, and only to the client. It is off by default
    because it helps on exactly one kind of path - one where a classifier
    throttles every flow it cannot name - and costs a round trip everywhere
    else. Switching it on blindly took two working tunnels down. Measure first:
    plain throughput stuck near 0.1 Mbit means the path needs it.

    The server accepts both shapes regardless, so changing this on a live
    tunnel can never strand the far end.
    """
    fwd = " ".join(f"-forward {p}:{p}" for p in ports)
    camo_flag = "" if camo else " -no-camo"
    allow = ",".join(ports)
    await log("اتصال به سرور خارج…")
    fc = await connect(foreign["host"], foreign["port"], foreign["user"], foreign["password"])
    await log("اتصال به سرور ایران…")
    ic = await connect(iran["host"], iran["port"], iran["user"], iran["password"], jump=jump)
    try:
        await log("نصب paytun روی سرور خارج (server)…")
        await _ship_paytun(fc)
        await run(fc, f"""set -e
install -d -m700 /etc/paytun; printf '%s' '{psk}' > /etc/paytun/psk; chmod 600 /etc/paytun/psk
cat > /etc/systemd/system/paytun-server.service <<U
[Unit]
Description=paytun server
After=network-online.target
[Service]
LimitNOFILE=1048576
ExecStart=/usr/local/bin/paytun -role server -port {port} -allow {allow}
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
U
systemctl daemon-reload; systemctl enable --now paytun-server; sleep 1
systemctl is-active paytun-server""")
        await log("نصب paytun روی سرور ایران (client)…")
        await _ship_paytun(ic)
        code, out = await run(ic, f"""set -e
install -d -m700 /etc/paytun; printf '%s' '{psk}' > /etc/paytun/psk; chmod 600 /etc/paytun/psk
cat > /etc/systemd/system/paytun-client.service <<U
[Unit]
Description=paytun client
After=network-online.target
[Service]
LimitNOFILE=1048576
ExecStart=/usr/local/bin/paytun -role client -server {foreign["host"]} -port {port} {fwd}{camo_flag}
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
U
systemctl daemon-reload; systemctl enable --now paytun-client; sleep 2
systemctl is-active paytun-client
for p in {' '.join(ports)}; do timeout 6 bash -c "cat </dev/null >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "port $p up" || echo "port $p down"; done""")
        return {"port": port, "check": out.strip()}
    finally:
        fc.close(); ic.close()


async def teardown_paytun(iran, foreign, detail, jump, log):
    await log("حذف paytun از سرور خارج…")
    try:
        fc = await connect(foreign["host"], foreign["port"], foreign["user"], foreign["password"])
        await run(fc, "systemctl disable --now paytun-server 2>/dev/null; "
                      "rm -f /etc/systemd/system/paytun-server.service; systemctl daemon-reload; true")
        fc.close()
    except Exception as e:
        await log(f"⚠️ خارج: {str(e)[:120]}")
    await log("حذف paytun از سرور ایران…")
    try:
        ic = await connect(iran["host"], iran["port"], iran["user"], iran["password"], jump=jump)
        await run(ic, "systemctl disable --now paytun-client 2>/dev/null; "
                      "rm -f /etc/systemd/system/paytun-client.service; systemctl daemon-reload; true")
        ic.close()
    except Exception as e:
        await log(f"⚠️ ایران: {str(e)[:120]}")


# --------------------------------------------------------------------------
# plain port forward (DNAT) on one server
# --------------------------------------------------------------------------
async def build_forward(server, src_port, dst_ip, dst_port, jump, is_iran, tid, log):
    table = f"cbfwd{tid}"
    await log("اتصال به سرور مبدأ…")
    conn = await connect(server["host"], server["port"], server["user"],
                         server["password"], jump=jump if is_iran else None)
    try:
        await log("برقراری فوروارد…")
        code, out = await run(conn, f"""set -e
sysctl -qw net.ipv4.ip_forward=1
nft list table ip {table} >/dev/null 2>&1 && nft delete table ip {table}
nft add table ip {table}
nft add chain ip {table} pre '{{ type nat hook prerouting priority dstnat; }}'
nft add chain ip {table} post '{{ type nat hook postrouting priority srcnat; }}'
nft add rule ip {table} pre tcp dport {src_port} counter dnat to {dst_ip}:{dst_port}
nft add rule ip {table} pre udp dport {src_port} counter dnat to {dst_ip}:{dst_port}
nft add rule ip {table} post ip daddr {dst_ip} counter masquerade
echo FWD_OK""")
        if "FWD_OK" not in out:
            raise RuntimeError(f"forward failed: {out[-300:]}")
        return {"table": table}
    finally:
        conn.close()


async def teardown_forward(server, detail, jump, is_iran, log):
    await log("حذف فوروارد…")
    conn = await connect(server["host"], server["port"], server["user"],
                         server["password"], jump=jump if is_iran else None)
    try:
        await run(conn, f"nft delete table ip {detail['table']} 2>/dev/null; true")
    finally:
        conn.close()
