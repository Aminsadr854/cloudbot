"""
Replace a server that stopped working, without the customers noticing.

Every config in the subscription points at a subdomain, not at a raw IP. That
one fact is what makes silent replacement possible: build a fresh server, node
it into the panel, repoint the subdomain, and the config in everybody's client
keeps working untouched. Nothing is torn down until the replacement has been
proven healthy from inside Iran - losing a working server to a failed rebuild
would be worse than the outage being fixed.

Two failure shapes are handled:

* one server filtered or dead -> rebuild it on the same account, same region,
  same plan.
* the whole account gone (suspended/banned, every server dark at once) ->
  rebuild on a DIFFERENT account in the same region, because a per-server
  retry against a dead account would just fail over and over.
"""
import asyncio
import ipaddress
import re
import socket

import providers

# Prefer a current LTS when rebuilding; the exact id differs per provider.
IMAGE_PREF = ("ubuntu 24", "ubuntu-24.04", "ubuntu24.04",
              "ubuntu 22", "ubuntu-22.04", "ubuntu22.04",
              "debian 12", "debian-12", "debian12")


class ReplaceError(Exception):
    pass


async def resolve(host):
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, None, family=socket.AF_INET)
        return sorted({i[4][0] for i in infos})
    except Exception:
        return []


def is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


async def account_servers(account):
    """(servers, banned). A refused listing is how a dead account announces itself."""
    try:
        return await providers.Provider(account).list_servers(), False
    except Exception as e:
        msg = str(e).lower()
        if any(x in msg for x in ("401", "403", "suspend", "unauthorized",
                                  "disabled", "banned")):
            return [], True
        raise


def looks_banned(servers):
    """
    Every server dark at once is an account-level event, not a server-level one.

    One stopped server is a stopped server; all of them stopped together is a
    suspension, and retrying per-server against it would burn attempts for
    nothing.
    """
    if len(servers) < 2:
        return False
    dead = 0
    for s in servers:
        state = (str(s.get("status") or "")).lower()
        if not any(x in state for x in ("running", "active", "ok")):
            dead += 1
    return dead == len(servers)


async def find_server(st, ip):
    """Locate which account a running IP belongs to. -> (account, server, banned)"""
    for acc in st.accounts():
        try:
            servers, banned = await account_servers(acc)
        except Exception:
            continue
        if banned:
            continue
        for s in servers:
            if s.get("ip") == ip:
                return acc, s, looks_banned(servers)
    return None, None, False


async def unreadable_accounts(st):
    """
    Accounts whose server list cannot be fetched right now, with the reason.

    find_server() skips these, because an account that returns nothing cannot be
    searched for an IP. Skipping is right; discarding the fact is not. A tunnel
    whose foreign server lives in a refused account looks exactly like a tunnel
    whose server was deleted - and the repair that follows wipes the Iran side
    and tries to SSH into a machine it can neither see nor replace, every time
    the watchdog comes round. Reporting which account went dark turns an endless
    rebuild loop into one sentence naming what to fix.

    Each entry is (account, reason, hard). `hard` separates an account that
    answered and said no - a dead token, a suspension - from one that merely
    failed to answer, which a flaky proxy or a timeout produces several times a
    day. Only the first justifies building a replacement server somewhere else;
    treating a 502 the same way would spend real money on a blip that clears by
    itself a minute later.
    """
    out = []
    for acc in st.accounts():
        try:
            servers, refused = await account_servers(acc)
            if refused:
                out.append((acc, "دسترسی رد شد (توکن باطل یا اکانت معلق)", True))
        except Exception as e:
            out.append((acc, str(e)[:120], False))
    return out


async def sibling_account(st, exclude_id, provider, region):
    """
    Another account of the same provider that can host the same region.

    Used when an account is banned: the customers' config has to come back in
    the same datacenter, so only the account changes, never the location.

    Among the candidates, the one carrying the FEWEST servers wins. Piling every
    replacement onto whichever account happens to be listed first would rebuild
    the same single point of failure that just cost us an account - and a
    thinly-loaded account is also the less conspicuous place to grow.
    """
    # provider=None means "any provider" - used when the owner accepts a
    # temporary home on whatever is alive until their own provider is back.
    candidates = []
    for acc in st.accounts():
        if acc["id"] == exclude_id:
            continue
        if provider is not None and acc["provider"] != provider:
            continue
        try:
            servers, banned = await account_servers(acc)
            if banned:
                continue
            regions = {r[0] if isinstance(r, (list, tuple)) else r
                       for r in await providers.Provider(acc).regions()}
        except Exception:
            continue
        if not regions or region in regions:
            candidates.append((len(servers), acc))
    if not candidates:
        return None
    candidates.sort(key=lambda c: c[0])
    return candidates[0][1]


async def pick_image(acc):
    imgs = await providers.Provider(acc).images()
    for want in IMAGE_PREF:
        for iid, label in imgs:
            hay = f"{iid} {label}".lower()
            if want in hay:
                return iid
    if not imgs:
        raise ReplaceError("هیچ ایمیجی از این اکانت برنگشت")
    return imgs[0][0]


def new_label(old_label, ip):
    """Keep the old name recognisable but unique; panels reject duplicates."""
    base = re.sub(r"-r\d+$", "", str(old_label or ip or "node"))
    n = 2
    m = re.search(r"-r(\d+)$", str(old_label or ""))
    if m:
        n = int(m.group(1)) + 1
    return f"{base}-r{n}"[:60]


async def build_replacement(st, acc, old_server, log):
    """
    Create + boot a same-spec server on `acc`. Returns the created server dict.
    """
    prov = providers.Provider(acc)
    image = await pick_image(acc)
    label = new_label(old_server.get("label"), old_server.get("ip"))
    await log(f"ساخت سرور نو روی «{acc['label']}» — {old_server.get('region')} / "
              f"{old_server.get('plan')}")
    import secrets
    import string
    pw = "".join(secrets.choice(string.ascii_letters + string.digits)
                 for _ in range(20)) + "A9!"
    srv = await prov.create_server(label, old_server["region"],
                                   old_server["plan"], image, pw)
    st.set_server_pass(acc["id"], srv["id"], srv["root_password"])

    # Vultr and friends hand back the IP a moment after creation.
    ip = srv.get("ip")
    for _ in range(30):
        if ip and ip not in ("(provisioning)", "0.0.0.0"):
            break
        await asyncio.sleep(10)
        try:
            cur = await prov.server(srv["id"])
            ip = cur.get("ip")
        except Exception:
            pass
    if not ip or ip in ("(provisioning)", "0.0.0.0"):
        raise ReplaceError("سرور ساخته شد ولی آی‌پی نگرفت")
    srv["ip"] = ip
    await log(f"سرور نو ساخته شد: <code>{ip}</code>")
    return srv


async def wait_port(ip, port, tries=20, delay=8):
    """Wait until a freshly built server answers at all (from here)."""
    for _ in range(tries):
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(ip, port),
                                          timeout=5)
            w.close()
            return True
        except Exception:
            await asyncio.sleep(delay)
    return False


async def scrap(st, account, srv, log):
    """Destroy a candidate that turned out to be unusable, and forget it."""
    try:
        await providers.Provider(account).delete_server(srv["id"])
        st.forget_server(account["id"], srv["id"])
    except Exception as e:
        await log(f"⚠️ حذف سرور آزمایشی نشد ({srv.get('ip')}): {str(e)[:120]}")
