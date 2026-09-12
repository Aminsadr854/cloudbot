"""
Keep the tunnelled configs alive.

A tunnelled config is not addressed by the server that serves it. The customer
dials an Iran relay; the relay forwards over a tunnel to a foreign box that does
the real work. So when such a config dies, the Iran side is usually fine and the
foreign side - or the account holding it - is what broke. That is why these are
repaired differently from direct configs: the fix is to rebuild the TUNNEL, not
to swap the address the customer dials.

The account is checked before anything else. Several tunnels normally share one
provider account, so a suspension takes them all down at once; repairing them
one at a time against a dead account would fail once per tunnel and waste the
retry budget. Discovering the ban first lets every affected tunnel move together.

Order of attack when a tunnel is down, cheapest first:
  1. rebuild it as-is (the daemon may simply have died)
  2. rebuild with the OTHER transport - GRE and paytun fail for different
     reasons, so the one that is not working is evidence for trying the other
  3. only then burn a new foreign server, which costs money and time
"""
import secrets
import string

import providers
import replacer
import tunnel as tun
import watchdog

OTHER_KIND = {"gre": "paytun", "paytun": "gre"}


def _ports(t):
    return [p for p in str(t.get("ports") or "9093").split(",") if p]


def _psk():
    return "".join(secrets.choice(string.ascii_letters + string.digits)
                   for _ in range(32))


def next_subnet(st):
    """GRE subnets must not collide across tunnels on the same relay."""
    used = {int(t["detail"].get("subnet_n") or 0) for t in st.tunnels()
            if t["kind"] == "gre"}
    n = 1
    while n in used:
        n += 1
    return n


def tunnel_for_ip(st, ip):
    """Which registered tunnel terminates on this Iran IP (if any)."""
    for t in st.tunnels():
        if (t.get("iran_host") or "").strip() == ip:
            return t
    return None


async def foreign_account(st, t):
    """(account, server, banned) for the tunnel's foreign end."""
    return await replacer.find_server(st, t.get("foreign_host"))


async def unreadable_accounts(st):
    """Accounts that cannot be listed right now, as (account, reason) pairs."""
    return await replacer.unreadable_accounts(st)


async def account_is_banned(st, acc):
    try:
        servers, refused = await replacer.account_servers(acc)
    except Exception:
        return False, []
    return (refused or replacer.looks_banned(servers)), servers


def tunnels_on_account(st, servers):
    """Every tunnel whose foreign end sits on this account's server list."""
    ips = {s.get("ip") for s in servers}
    return [t for t in st.tunnels() if t.get("foreign_host") in ips]


async def probe(st, iran_host, port, log=None):
    """Is the tunnelled port answering from inside Iran?"""
    res = await watchdog.run_probes(
        st.cfscan()["ssh"], st.jump(),
        [{"id": 0, "label": "tunnel", "host": iran_host, "port": int(port),
          "tls": False}])
    ok = bool(res) and (res[0].get("tcp_ratio") or 0) >= 0.5
    if log:
        await log(("✅ تانل از ایران جواب می‌دهد" if ok
                   else "❌ تانل از ایران جواب نمی‌دهد") +
                  (f" — {watchdog.describe(res[0])}" if res else ""))
    return ok


# Everything this bot builds is named with a "cb" prefix, so a wipe can be
# thorough without touching anything the owner set up by hand.
IRAN_CLEAN = r"""
# `ip -o link show` prints a GRE device as "cbgre3@NONE"; feeding that name
# straight to `ip link del` fails with "Cannot find device", and because the
# failure was silenced the wipe reported success while deleting nothing. The
# leftover then owns the local/remote pair, so every later `ip tunnel add`
# fails with EEXIST and no rebuild can ever succeed.
for d in $(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1 | grep -E '^cbgre'); do
  ip link del "$d" 2>/dev/null
done
systemctl disable --now paytun-client >/dev/null 2>&1
rm -f /etc/systemd/system/paytun-client.service
systemctl daemon-reload >/dev/null 2>&1
nft delete table ip cbtun >/dev/null 2>&1
echo IRAN_CLEAN_OK
"""

def foreign_clean_script(dev=None):
    if dev:
        return f"""
ip link del "{dev}" 2>/dev/null || true
echo FOREIGN_CLEAN_OK
"""
    return r"""
# `ip -o link show` prints a GRE device as "cbgre3@NONE"; feeding that name
# straight to `ip link del` fails with "Cannot find device", and because the
# failure was silenced the wipe reported success while deleting nothing. The
# leftover then owns the local/remote pair, so every later `ip tunnel add`
# fails with EEXIST and no rebuild can ever succeed.
for d in $(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1 | grep -E '^cbgre'); do
  ip link del "$d" 2>/dev/null
done
systemctl disable --now paytun-server >/dev/null 2>&1
rm -f /etc/systemd/system/paytun-server.service
systemctl daemon-reload >/dev/null 2>&1
echo FOREIGN_CLEAN_OK
"""


async def wipe(iran, foreign, jump, log, dev=None):
    """
    Remove the old tunnel on these two machines without disturbing other tunnels
    sharing the same foreign server.
    """
    await log("پاک‌سازی تانل قبلی روی سرور ایران…")
    try:
        ic = await tun.connect(iran["host"], iran["port"], iran["user"],
                               iran["password"], jump=jump)
        try:
            # On Iran relay, delete the specific device if known, or wipe cbgre
            cmd = f'ip link del "{dev}" 2>/dev/null || true; echo IRAN_CLEAN_OK' if dev else IRAN_CLEAN
            code, out = await tun.run(ic, cmd)
            if "IRAN_CLEAN_OK" not in out:
                await log(f"⚠️ پاک‌سازی ایران کامل نشد: {out[-120:]}")
        finally:
            ic.close()
    except Exception as e:
        # A relay we cannot reach cannot be carrying a conflicting tunnel we
        # are about to double up on, so this is a warning, not a stop.
        await log(f"⚠️ اتصال به سرور ایران برای پاک‌سازی نشد: {str(e)[:120]}")

    if not foreign or not foreign.get("host"):
        return
    try:
        fc = await tun.connect(foreign["host"], foreign["port"],
                               foreign["user"], foreign["password"])
        try:
            await tun.run(fc, foreign_clean_script(dev))
        finally:
            fc.close()
    except Exception as e:
        await log(f"⚠️ پاک‌سازی سرور خارج نشد: {str(e)[:120]}")


async def build(st, t, kind, iran, foreign, jump, log):
    """Build `kind` between these two ends and return the new detail dict."""
    ports = _ports(t)
    if kind == "gre":
        detail = await tun.build_gre(iran, foreign, ports, jump,
                                     next_subnet(st), log)
    else:
        detail = await tun.build_paytun(iran, foreign, ports, jump,
                                        _psk(), 8443, log)
    detail["iran"] = iran
    detail["foreign"] = foreign
    return detail


async def rebuild(st, t, *, kind=None, foreign=None, jump, log):
    """
    Re-establish one tunnel, then prove it from Iran.

    Returns (ok, new_tunnel_id). The store record is replaced only when the
    rebuild actually answers - a half-built tunnel recorded as good would hide
    the outage instead of fixing it.
    """
    d = t["detail"]
    iran = d["iran"]
    foreign = foreign or d["foreign"]
    kind = kind or t["kind"]

    # Wipe BOTH ends before building: the Iran side so nothing competes for
    # the port, the old foreign side because it is either being reused or
    # thrown away. Skipped only for a brand-new box that never had a tunnel.
    await wipe(iran, d.get("foreign"), jump, log, dev=d.get("dev"))
    await log(f"برپاسازی تانل {kind} — ایران {iran['host']} ← خارج {foreign['host']}")
    detail = await build(st, t, kind, iran, foreign, jump, log)

    ok = await probe(st, iran["host"], _ports(t)[0], log)
    if not ok:
        return False, None

    st.delete_tunnel(t["id"])
    tid = st.add_tunnel(kind, iran["host"], foreign["host"],
                        ",".join(_ports(t)), detail)
    return True, tid


async def new_foreign_server(st, acc, template_server, log):
    """
    A fresh foreign endpoint on `acc`, matching the old one's size and region.

    Reuses the replacement builder so a tunnel endpoint is created exactly the
    way a node endpoint is - same image policy, same wait-for-IP handling.
    """
    srv = await replacer.build_replacement(st, acc, template_server, log)
    ok = await replacer.wait_port(srv["ip"], 22, tries=20, delay=8)
    if not ok:
        await replacer.scrap(st, acc, srv, log)
        raise RuntimeError(f"سرور نو {srv['ip']} بالا نیامد")
    return {"host": srv["ip"], "port": 22, "user": "root",
            "password": srv["root_password"]}, srv
