"""
Read a subscription link and pull the real endpoints out of it.

The owner should never have to retype what the panel already knows, so the
watchdog imports its targets straight from the subscription: fetch it, decode
it, and work out for each config which host and port a client actually dials,
and whether that dial is wrapped in TLS.

Two details matter for probing correctly:

* The address a client connects to is not always the address in the link. For
  a CDN config the client dials the CDN edge and the real server hides behind
  an SNI/Host header, so those are classified separately - probing a Cloudflare
  edge tells you nothing about whether YOUR server is alive.
* UDP protocols (hysteria2, tuic) cannot be probed with a TCP connect at all,
  so they are reported and skipped rather than silently marked down.
"""
import asyncio
import base64
import ipaddress
import json
import socket
from urllib.parse import parse_qs, unquote, urlparse

import aiohttp

# Ask as a client that gets plain links back rather than a JSON config blob.
UA = "v2rayNG/1.8.23"

TCP_PROTOCOLS = ("vless", "vmess", "trojan", "ss")
UDP_PROTOCOLS = ("hysteria2", "hy2", "tuic")


def _b64_fix(s: str) -> bytes:
    s = s.strip().replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4))


async def fetch(url: str) -> list:
    """Fetch a subscription and return the raw config URIs it contains."""
    timeout = aiohttp.ClientTimeout(total=45)
    async with aiohttp.ClientSession(timeout=timeout,
                                     headers={"User-Agent": UA}) as s:
        async with s.get(url) as r:
            if r.status != 200:
                raise RuntimeError(f"HTTP {r.status} از لینک ساب")
            body = (await r.text()).strip()
    if not body:
        raise RuntimeError("لینک ساب خالی برگشت")

    # A subscription is either a base64 blob or already one URI per line.
    if "://" not in body:
        try:
            body = _b64_fix(body).decode("utf-8", "replace")
        except Exception:
            raise RuntimeError("محتوای لینک ساب قابل خواندن نبود")
    return [ln.strip() for ln in body.splitlines() if "://" in ln]


def parse_uri(uri: str):
    """One config URI -> {label, host, port, tls, sni, proto} (or None)."""
    scheme = uri.split("://", 1)[0].lower()
    try:
        if scheme == "vmess":
            return _parse_vmess(uri)
        if scheme in ("vless", "trojan"):
            return _parse_vless_like(uri, scheme)
        if scheme == "ss":
            return _parse_ss(uri)
        if scheme in UDP_PROTOCOLS:
            u = urlparse(uri)
            return {"proto": scheme, "host": u.hostname, "port": u.port or 443,
                    "tls": True, "sni": None, "udp": True,
                    "label": unquote(u.fragment) or u.hostname}
    except Exception:
        return None
    return None


def _parse_vless_like(uri, scheme):
    u = urlparse(uri)
    q = parse_qs(u.query)
    sec = (q.get("security", [""])[0] or "").lower()
    # trojan is TLS unless it explicitly says otherwise.
    tls = sec in ("tls", "reality", "xtls") or (scheme == "trojan" and sec != "none")
    sni = (q.get("sni", [None])[0] or q.get("host", [None])[0]
           or q.get("peer", [None])[0])
    return {"proto": scheme, "host": u.hostname, "port": u.port or 443,
            "tls": tls, "sni": sni, "udp": False,
            "label": unquote(u.fragment) or u.hostname}


def _parse_vmess(uri):
    raw = uri.split("://", 1)[1]
    cfg = json.loads(_b64_fix(raw).decode("utf-8", "replace"))
    tls = str(cfg.get("tls", "")).lower() in ("tls", "reality", "true", "1")
    return {"proto": "vmess", "host": cfg.get("add"),
            "port": int(cfg.get("port") or 443), "tls": tls,
            "sni": cfg.get("sni") or cfg.get("host") or None, "udp": False,
            "label": cfg.get("ps") or cfg.get("add")}


def _parse_ss(uri):
    u = urlparse(uri)
    host, port = u.hostname, u.port
    if not host:
        # ss://BASE64(method:pass@host:port)#name
        body = uri.split("://", 1)[1].split("#")[0]
        dec = _b64_fix(body).decode("utf-8", "replace")
        hostport = dec.rsplit("@", 1)[-1]
        host, _, p = hostport.rpartition(":")
        port = int(p)
    return {"proto": "ss", "host": host, "port": port or 443, "tls": False,
            "sni": None, "udp": False,
            "label": unquote(u.fragment) or host}


# ---------------------------------------------------------------- CDN check
_CF_NETS: list = []


async def _cf_nets():
    global _CF_NETS
    if _CF_NETS:
        return _CF_NETS
    nets = []
    try:
        timeout = aiohttp.ClientTimeout(total=20)
        async with aiohttp.ClientSession(timeout=timeout) as s:
            for u in ("https://www.cloudflare.com/ips-v4",
                      "https://www.cloudflare.com/ips-v6"):
                async with s.get(u) as r:
                    if r.status == 200:
                        for ln in (await r.text()).split():
                            try:
                                nets.append(ipaddress.ip_network(ln.strip()))
                            except ValueError:
                                pass
    except Exception:
        pass
    _CF_NETS = nets
    return nets


async def _resolve(host):
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, None)
        return sorted({i[4][0] for i in infos})
    except Exception:
        return []


async def classify(configs: list) -> list:
    """
    Mark each config 'cdn' or 'direct'.

    A config whose address resolves into Cloudflare space is fronted by the
    CDN: probing it measures Cloudflare's edge, not the owner's server, so the
    watchdog treats those differently from direct ones.
    """
    nets = await _cf_nets()

    async def one(c):
        ips = await _resolve(c["host"]) if c.get("host") else []
        c["ips"] = ips
        cdn = False
        for ip in ips:
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if any(addr in n for n in nets):
                cdn = True
                break
        c["cdn"] = cdn
        return c

    return list(await asyncio.gather(*(one(c) for c in configs)))


def is_real_endpoint(host: str) -> bool:
    """
    Reject the informational rows panels put in subscriptions.

    Marzban-style panels ship a fake entry whose name carries the remaining
    quota or expiry date and whose address is 0.0.0.0. It is not a server, so
    watching it would mean alerting forever that a config nobody dials is down.
    """
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return True          # a hostname; resolution is checked later
    return not (addr.is_unspecified or addr.is_loopback
                or addr.is_link_local or addr.is_multicast)


async def load(url: str) -> list:
    """Fetch, parse, de-duplicate and classify a whole subscription."""
    uris = await fetch(url)
    out, seen = [], set()
    for uri in uris:
        c = parse_uri(uri)
        if not c or not c.get("host") or not c.get("port"):
            continue
        if not is_real_endpoint(c["host"]):
            continue
        key = (c["host"], c["port"], c["tls"])
        if key in seen:
            continue
        seen.add(key)
        out.append(c)
    return await classify(out)
