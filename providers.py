"""
Linode and Vultr, behind one interface.

Every request goes through the account's own proxy when it has one, because the
accounts may sit in different countries and a provider can refuse or mis-geo a
call that arrives from the wrong place. The proxy is given as
host:port:user:pass and turned into an authenticated HTTP proxy here.

Only the handful of operations the bot exposes are implemented - list, create,
delete servers, and the lookups needed to offer sane choices when creating one.
Nothing is cached: a token or proxy can change between calls, so each call
builds its own client.
"""
import asyncio
import ipaddress
import logging
import socket

import aiohttp
from yarl import URL

try:
    from aiohttp_socks import ProxyConnector
except Exception:  # pragma: no cover
    ProxyConnector = None

log = logging.getLogger("cloudbot.providers")

LINODE = "https://api.linode.com/v4"
VULTR = "https://api.vultr.com/v2"
HETZNER = "https://api.hetzner.cloud/v1"


# Server responses only carry a provider-specific location id, while the
# regions/locations endpoints include the country separately. Keep a small
# fallback for existing servers so their summaries can still show a flag
# without an extra API request on every screen.
_REGION_COUNTRIES = {
    "linode": {
        "us-east": "US", "us-central": "US", "us-west": "US",
        "us-southeast": "US", "us-iad": "US", "us-lax": "US",
        "us-sea": "US", "us-mia": "US", "us-ord": "US",
        "ca-central": "CA", "ca-central-1": "CA",
        "eu-west": "GB", "eu-central": "DE", "fr-par": "FR",
        "de-fra": "DE", "nl-ams": "NL", "it-mil": "IT",
        "se-sto": "SE", "es-mad": "ES", "gb-lon": "GB",
        "pl-waw": "PL", "br-gru": "BR", "in-bom": "IN",
        "in-maa": "IN", "sg-sin": "SG", "jp-tyo": "JP",
        "au-mel": "AU", "au-syd": "AU", "id-cgk": "ID",
        "mx-mex": "MX", "il-ost": "IL",
    },
    "vultr": {
        "ams": "NL", "fra": "DE", "lhr": "GB", "man": "GB",
        "par": "FR", "mad": "ES", "waw": "PL", "sto": "SE",
        "jnb": "ZA", "cpt": "ZA", "del": "IN",
        "bom": "IN", "blr": "IN", "sgp": "SG", "nrt": "JP",
        "icn": "KR", "syd": "AU", "mel": "AU", "akl": "NZ",
        "sao": "BR", "ord": "US", "dfw": "US", "lax": "US",
        "mia": "US", "atl": "US", "ewr": "US", "sea": "US",
        "sjc": "US", "yto": "CA", "tor": "CA", "mex": "MX",
        "dxb": "AE", "tlv": "IL", "ist": "TR",
    },
    "hetzner": {
        "ash": "US", "ash-dc1": "US", "hil": "US", "hil-dc1": "US",
        "fsn1": "DE", "nbg1": "DE", "hel1": "FI", "sin": "SG",
        "falkenstein": "DE", "nuremberg": "DE", "helsinki": "FI",
        "ashburn": "US", "hillsboro": "US", "singapore": "SG",
    },
}

_COUNTRY_ALIASES = {
    "UNITED STATES": "US", "USA": "US", "UNITED KINGDOM": "GB", "UK": "GB",
    "GERMANY": "DE", "DEUTSCHLAND": "DE", "FRANCE": "FR",
    "NETHERLANDS": "NL", "THE NETHERLANDS": "NL", "SPAIN": "ES",
    "POLAND": "PL", "SWEDEN": "SE", "FINLAND": "FI", "CANADA": "CA",
    "BRAZIL": "BR", "INDIA": "IN", "SINGAPORE": "SG", "JAPAN": "JP",
    "AUSTRALIA": "AU", "NEW ZEALAND": "NZ", "SOUTH AFRICA": "ZA",
    "SOUTH KOREA": "KR", "ISRAEL": "IL", "TURKEY": "TR",
    "UNITED ARAB EMIRATES": "AE", "MEXICO": "MX", "INDONESIA": "ID",
}


def country_code(value):
    """Return a two-letter ISO country code when ``value`` identifies one."""
    if value is None:
        return None
    value = str(value).strip().upper()
    if len(value) == 2 and value.isalpha():
        return value
    return _COUNTRY_ALIASES.get(value)


def country_flag(country):
    """Return the Telegram flag emoji for a country, or an empty string."""
    code = country_code(country)
    if not code:
        return ""
    return "".join(chr(0x1F1E6 + ord(letter) - ord("A")) for letter in code)


def region_country(provider, region):
    """Resolve a provider location id to a country when it is known locally."""
    key = str(region or "").strip().lower()
    country = _REGION_COUNTRIES.get(provider, {}).get(key)
    if country:
        return country
    # Linode location ids commonly start with their ISO country code.
    prefix = key.split("-", 1)[0]
    if len(prefix) == 2 and prefix.isalpha():
        return country_code(prefix)
    return None


def location_text(provider, region, country=None):
    """Format a location with its country flag while preserving its name/id."""
    value = str(region or "—")
    flag = country_flag(country or region_country(provider, region))
    return f"{flag} {value}" if flag else value


def proxy_url(proxy: str | None) -> str | None:
    """
    Turn the user's proxy string into a full proxy URL.

    Accepts, in order of preference:
      scheme://host:port:user:pass   (scheme = http/https/socks5/socks4)
      scheme://user:pass@host:port
      host:port:user:pass            (assumed http - the format the user gives)
      [ipv6]:port:user:pass          (IPv6 literals must be bracketed)
      host:port

    A bare host:port:user:pass is treated as HTTP because that is what the user
    was asked for; a SOCKS proxy can be selected by prefixing socks5://.
    """
    if not proxy:
        return None
    proxy = proxy.strip()
    scheme = "http"
    if "://" in proxy:
        scheme, proxy = proxy.split("://", 1)
    # already in url auth form?
    if "@" in proxy:
        return f"{scheme}://{proxy}"
    if proxy.startswith("["):
        end = proxy.find("]")
        if end < 0 or len(proxy) <= end + 2 or proxy[end + 1] != ":":
            raise ValueError("IPv6 proxy hosts must look like [2001:db8::1]:port")
        host = proxy[:end + 1]
        rest = proxy[end + 2:].split(":", 2)
        if len(rest) == 3:
            port, user, pw = rest
            return f"{scheme}://{user}:{pw}@{host}:{port}"
        if len(rest) == 1:
            return f"{scheme}://{host}:{rest[0]}"
    else:
        parts = proxy.split(":", 3)
        if len(parts) == 4:
            host, port, user, pw = parts
            return f"{scheme}://{user}:{pw}@{host}:{port}"
        if len(parts) == 2:
            host, port = parts
            return f"{scheme}://{host}:{port}"
    raise ValueError("proxy must be host:port or host:port:user:pass "
                     "(optionally prefixed with socks5://; bracket IPv6 hosts)")


async def proxy_for_family(proxy: str | None, family: str = "default") -> str | None:
    """Resolve a proxy hostname to the requested address family.

    The provider API still travels through the same proxy.  Only the TCP
    connection from Cloudbot to that proxy is pinned to IPv4 or IPv6.  This is
    important for dual-stack proxy hostnames whose two addresses behave
    differently from the server running Cloudbot.
    """
    if not proxy or family == "default":
        return proxy
    if family not in ("ipv4", "ipv6"):
        raise ProviderError("proxy family must be default, ipv4, or ipv6")
    parsed = URL(proxy)
    host = parsed.host
    if not host:
        raise ProviderError("proxy URL has no host")
    wanted = socket.AF_INET if family == "ipv4" else socket.AF_INET6
    try:
        literal = ipaddress.ip_address(host)
        if literal.version != (4 if family == "ipv4" else 6):
            raise ProviderError(f"proxy is {literal.version == 4 and 'IPv4' or 'IPv6'}, not {family.upper()}")
        return proxy
    except ValueError:
        pass
    try:
        rows = await asyncio.get_running_loop().getaddrinfo(
            host, parsed.port, family=wanted, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise ProviderError(f"proxy host has no {family.upper()} address: {host}") from e
    if not rows:
        raise ProviderError(f"proxy host has no {family.upper()} address: {host}")
    return str(parsed.with_host(rows[0][4][0]))


class ProviderError(Exception):
    pass


class Provider:
    def __init__(self, account: dict):
        self.provider = account["provider"]
        self.token = account["token"]
        self.proxy = proxy_url(account.get("proxy"))
        self.proxy_family = account.get("proxy_family", "default")

    def _base(self):
        return {"linode": LINODE, "vultr": VULTR, "hetzner": HETZNER}[self.provider]

    async def _req(self, method, path, **kw):
        headers = {"Authorization": f"Bearer {self.token}",
                   "Content-Type": "application/json"}
        timeout = aiohttp.ClientTimeout(total=45)
        url = self._base() + path
        proxy = await proxy_for_family(self.proxy, self.proxy_family)
        is_socks = bool(proxy) and proxy.startswith(("socks5", "socks4"))

        try:
            if is_socks:
                # A SOCKS proxy cannot be passed as aiohttp's proxy= (that is
                # HTTP-proxy only); it has to be the session's connector.
                if ProxyConnector is None:
                    raise ProviderError("SOCKS proxy needs aiohttp-socks installed")
                conn = ProxyConnector.from_url(proxy)
                async with aiohttp.ClientSession(timeout=timeout, connector=conn) as s:
                    async with s.request(method, url, headers=headers, **kw) as r:
                        text = await r.text()
                        if r.status >= 400:
                            raise ProviderError(f"HTTP {r.status}: {text[:300]}")
                        return await r.json() if text.strip() else {}
            else:
                async with aiohttp.ClientSession(timeout=timeout) as s:
                    async with s.request(method, url, headers=headers,
                                         proxy=proxy or None, **kw) as r:
                        text = await r.text()
                        if r.status >= 400:
                            raise ProviderError(f"HTTP {r.status}: {text[:300]}")
                        return await r.json() if text.strip() else {}
        except ProviderError:
            raise
        except Exception as e:
            # Surface the concrete transport failure (proxy refused, TLS, DNS)
            # instead of a generic "connection failed".
            log.warning("request %s %s via proxy=%s failed: %s",
                        method, path, proxy, e)
            raise ProviderError(f"{type(e).__name__}: {str(e)[:250]}")

    # -- connectivity check (also validates token + proxy together) ------
    async def whoami(self):
        if self.provider == "linode":
            d = await self._req("GET", "/profile")
            return d.get("username") or d.get("email") or "linode account"
        if self.provider == "vultr":
            d = await self._req("GET", "/account")
            acc = d.get("account", d)
            return acc.get("email") or acc.get("name") or "vultr account"
        # hetzner: token is project-scoped, no account endpoint; a cheap call
        # that any valid token can make doubles as the validation.
        await self._req("GET", "/servers?per_page=1")
        return "Hetzner project"

    async def account_info(self):
        """Fetch account details, credit, balance, and charges if supported."""
        if self.provider == "vultr":
            d = await self._req("GET", "/account")
            acc = d.get("account", d)
            balance = float(acc.get("balance", 0.0))
            pending = float(acc.get("pending_charges", 0.0))
            credit = -balance if balance < 0 else 0.0
            owed = balance if balance > 0 else 0.0
            net = credit - pending if credit > 0 else -(owed + pending)
            last_pay_amt = acc.get("last_payment_amount")
            last_pay_date = (acc.get("last_payment_date") or "").split("T")[0]
            return {
                "name": acc.get("name"),
                "email": acc.get("email"),
                "balance": balance,
                "credit": credit,
                "owed": owed,
                "pending_charges": pending,
                "net": net,
                "last_payment_amount": abs(float(last_pay_amt)) if last_pay_amt is not None else None,
                "last_payment_date": last_pay_date or None,
            }
        if self.provider == "linode":
            acc = await self._req("GET", "/account")
            promos = acc.get("active_promotions", [])
            promo_credit = sum(float(p.get("credit_remaining", 0.0)) for p in promos)
            bal = float(acc.get("balance", 0.0))
            uninvoiced = float(acc.get("balance_uninvoiced", 0.0))
            name = f"{acc.get('first_name', '')} {acc.get('last_name', '')}".strip() or acc.get("company")
            return {
                "name": name or None,
                "email": acc.get("email"),
                "balance": bal,
                "credit": promo_credit if promo_credit > 0 else (-bal if bal < 0 else 0.0),
                "owed": bal if bal > 0 else 0.0,
                "pending_charges": uninvoiced,
                "net": promo_credit - uninvoiced if promo_credit > 0 else -uninvoiced,
            }
        return None

    # -- list servers ----------------------------------------------------
    async def list_servers(self):
        if self.provider == "linode":
            d = await self._req("GET", "/linode/instances?page_size=200")
            out = []
            for i in d.get("data", []):
                out.append({
                    "id": i["id"], "label": i.get("label"),
                    "region": i.get("region"),
                    "country": region_country(self.provider, i.get("region")),
                    "ip": (i.get("ipv4") or [None])[0],
                    "status": i.get("status"),
                    "plan": i.get("type"),
                })
            return out
        if self.provider == "vultr":
            d = await self._req("GET", "/instances?per_page=200")
            out = []
            for i in d.get("instances", []):
                out.append({
                    "id": i["id"], "label": i.get("label") or i.get("hostname"),
                    "region": i.get("region"),
                    "country": region_country(self.provider, i.get("region")),
                    "ip": i.get("main_ip") if i.get("main_ip", "0.0.0.0") != "0.0.0.0" else "(provisioning)",
                    "status": i.get("status") + "/" + i.get("power_status", ""),
                    "plan": i.get("plan"),
                })
            return out
        # hetzner
        d = await self._req("GET", "/servers?per_page=50")
        out = []
        for i in d.get("servers", []):
            location = (i.get("datacenter") or {}).get("location") or {}
            ipv4 = ((i.get("public_net") or {}).get("ipv4") or {}).get("ip")
            out.append({
                "id": i["id"], "label": i.get("name"),
                "region": location.get("name"),
                "country": country_code(location.get("country_iso") or location.get("country"))
                           or region_country(self.provider, location.get("name")),
                "ip": ipv4 or "(provisioning)",
                "status": i.get("status"),
                "plan": (i.get("server_type") or {}).get("name"),
            })
        return out

    async def server(self, server_id):
        if self.provider == "linode":
            i = await self._req("GET", f"/linode/instances/{server_id}")
            return {"id": i["id"], "label": i.get("label"), "region": i.get("region"),
                    "country": region_country(self.provider, i.get("region")),
                    "ip": (i.get("ipv4") or [None])[0], "status": i.get("status"),
                    "plan": i.get("type")}
        if self.provider == "vultr":
            d = await self._req("GET", f"/instances/{server_id}")
            i = d.get("instance", d)
            return {"id": i["id"], "label": i.get("label"), "region": i.get("region"),
                    "country": region_country(self.provider, i.get("region")),
                    "ip": i.get("main_ip"), "status": i.get("status"),
                    "plan": i.get("plan"), "default_password": i.get("default_password")}
        # hetzner
        d = await self._req("GET", f"/servers/{server_id}")
        i = d.get("server", d)
        location = (i.get("datacenter") or {}).get("location") or {}
        ipv4 = ((i.get("public_net") or {}).get("ipv4") or {}).get("ip")
        return {"id": i["id"], "label": i.get("name"),
                "region": location.get("name"),
                "country": country_code(location.get("country_iso") or location.get("country"))
                           or region_country(self.provider, location.get("name")),
                "ip": ipv4, "status": i.get("status"),
                "plan": (i.get("server_type") or {}).get("name")}

    # -- choices for creation --------------------------------------------
    async def regions(self):
        if self.provider == "linode":
            d = await self._req("GET", "/regions?page_size=200")
            return [(r["id"], location_text(self.provider,
                                              r.get("label") or r["id"],
                                              r.get("country")))
                    for r in d.get("data", [])]
        if self.provider == "vultr":
            d = await self._req("GET", "/regions?per_page=200")
            return [(r["id"], location_text(
                        self.provider,
                        f"{r.get('city','')} {r.get('country','')}".strip() or r["id"],
                        r.get("country")))
                    for r in d.get("regions", [])]
        # hetzner
        d = await self._req("GET", "/locations?per_page=50")
        return [(l["name"], location_text(
                    self.provider,
                    f"{l.get('city','')} {l.get('country','')}".strip() or l["name"],
                    l.get("country_iso") or l.get("country")))
                for l in d.get("locations", [])]

    async def plans(self, region=None):
        if self.provider == "linode":
            d = await self._req("GET", "/linode/types?page_size=500")
            out = []
            for t in d.get("data", []):
                price = (t.get("price") or {}).get("monthly")
                transfer = t.get("transfer")
                traffic = f" · 📡 {transfer} GB traffic" if transfer is not None else ""
                out.append((t["id"],
                            f"{t.get('label', t['id'])}{traffic} - ${price}/mo"))
            return out
        if self.provider == "vultr":
            path = f"/plans?per_page=500" + (f"&region={region}" if region else "")
            d = await self._req("GET", path)
            out = []
            for p in d.get("plans", []):
                out.append((p["id"], f"{p.get('vcpu_count')}vCPU {p.get('ram')}MB "
                                     f"{p.get('disk')}GB - ${p.get('monthly_cost')}/mo"))
            return out
        # hetzner: server types; show only those available in the chosen location,
        # and take the monthly price for that location.
        d = await self._req("GET", "/server_types?per_page=100")
        out = []
        for t in d.get("server_types", []):
            if t.get("deprecated"):
                continue
            price = ""
            for pr in t.get("prices", []):
                if not region or pr.get("location") == region:
                    monthly = (pr.get("price_monthly") or {}).get("gross")
                    if monthly:
                        price = f" - €{float(monthly):.2f}/mo"
                    break
            else:
                # not offered in this location
                if region:
                    continue
            out.append((t["name"], f"{t['name']} · {t.get('cores')}vCPU "
                                   f"{t.get('memory')}GB {t.get('disk')}GB{price}"))
        return out

    async def images(self):
        if self.provider == "linode":
            d = await self._req("GET", "/images?page_size=500")
            imgs = [i for i in d.get("data", []) if i.get("is_public")]
            # Prefer the mainstream distributions; the full list is huge.
            pref = [i for i in imgs if any(x in i["id"] for x in
                    ("ubuntu22.04", "ubuntu24.04", "debian12", "debian11"))]
            chosen = pref or imgs
            return [(i["id"], i.get("label") or i["id"]) for i in chosen[:40]]
        if self.provider == "vultr":
            d = await self._req("GET", "/os?per_page=500")
            oss = d.get("os", [])
            pref = [o for o in oss if any(x in o.get("name", "").lower()
                    for x in ("ubuntu 22", "ubuntu 24", "debian 12", "debian 11"))]
            chosen = pref or oss
            return [(str(o["id"]), o.get("name")) for o in chosen[:40]]
        # hetzner system images; the image "name" (e.g. ubuntu-22.04) is what
        # create expects.
        d = await self._req("GET", "/images?type=system&per_page=100")
        imgs = d.get("images", [])
        pref = [i for i in imgs if any(x in (i.get("name") or "")
                for x in ("ubuntu-22.04", "ubuntu-24.04", "debian-12", "debian-11"))]
        chosen = pref or imgs
        return [(i.get("name") or str(i["id"]),
                 i.get("description") or i.get("name")) for i in chosen[:40]]

    # -- create ----------------------------------------------------------
    async def create_server(self, label, region, plan, image, root_password):
        """Returns {id, ip, label, root_password, default_password?}."""
        if self.provider == "linode":
            body = {
                "label": label, "region": region, "type": plan, "image": image,
                "root_pass": root_password,
                "booted": True,
            }
            i = await self._req("POST", "/linode/instances", json=body)
            return {"id": i["id"], "label": i.get("label"),
                    "ip": (i.get("ipv4") or [None])[0], "region": i.get("region"),
                    "country": region_country(self.provider, i.get("region")),
                    "plan": i.get("type"), "root_password": root_password}
        if self.provider == "vultr":
            body = {
                "label": label, "region": region, "plan": plan, "os_id": int(image),
                "hostname": label,
            }
            d = await self._req("POST", "/instances", json=body)
            i = d.get("instance", d)
            # Vultr sets the root password itself and returns it once, on creation.
            return {"id": i["id"], "label": i.get("label"),
                    "ip": i.get("main_ip") if i.get("main_ip", "0.0.0.0") != "0.0.0.0" else None,
                    "region": i.get("region"), "plan": i.get("plan"),
                    "country": region_country(self.provider, i.get("region")),
                    "root_password": i.get("default_password") or root_password}
        # hetzner: with no ssh_keys attached, Hetzner generates a root password
        # and returns it once in the create response - which is what node-it needs.
        body = {
            "name": label, "server_type": plan, "image": image,
            "location": region, "start_after_create": True,
        }
        d = await self._req("POST", "/servers", json=body)
        i = d.get("server", d)
        location = (i.get("datacenter") or {}).get("location") or {}
        ipv4 = ((i.get("public_net") or {}).get("ipv4") or {}).get("ip")
        return {"id": i["id"], "label": i.get("name"), "ip": ipv4,
                "region": location.get("name"),
                "country": country_code(location.get("country_iso") or location.get("country"))
                           or region_country(self.provider, location.get("name")),
                "plan": (i.get("server_type") or {}).get("name"),
                "root_password": d.get("root_password") or root_password}

    async def reset_root_password(self, server_id):
        """
        Have the provider set a new root password and hand it back.

        Only Hetzner does this in one call that returns the password: it
        generates one, applies it, and reboots the machine. The other two have
        no equivalent - Linode's endpoint takes a password you supply and only
        works on a powered-off instance, and Vultr offers none - so they are
        refused outright instead of being half-supported.

        The reboot is why this is not offered silently: callers confirm first.
        """
        if self.provider != "hetzner":
            raise ProviderError(
                f"{self.provider} has no reset-root-password API; "
                "only Hetzner supports this."
            )
        d = await self._req("POST", f"/servers/{server_id}/actions/reset_password")
        pw = d.get("root_password")
        if not pw:
            # Hetzner answers with the action alone when it could not reach the
            # guest agent. Reporting that plainly beats handing back a blank
            # password the caller would then save over a working one.
            raise ProviderError(
                f"Hetzner returned no password (is the server running?): {str(d)[:200]}"
            )
        return pw

    async def delete_server(self, server_id):
        if self.provider == "linode":
            await self._req("DELETE", f"/linode/instances/{server_id}")
        elif self.provider == "vultr":
            await self._req("DELETE", f"/instances/{server_id}")
        else:
            await self._req("DELETE", f"/servers/{server_id}")
        return True

    # -- Vultr public IPs ------------------------------------------------
    async def add_vultr_ipv4(self, server_id):
        """Attach another public IPv4 to a Vultr instance and reboot it."""
        if self.provider != "vultr":
            raise ProviderError("additional public IPv4 is only available for Vultr")
        return await self._req("POST", f"/instances/{server_id}/ipv4",
                               json={"reboot": True})

    async def create_and_attach_vultr_floating_ip(self, server_id, region, label):
        """Create a Vultr Reserved IPv4 and attach it to the given instance."""
        if self.provider != "vultr":
            raise ProviderError("floating IP is only available for Vultr")
        created = await self._req("POST", "/reserved-ips", json={
            "region": region, "ip_type": "v4", "label": label[:128],
        })
        reserved = created.get("reserved_ip", created)
        reserved_id = reserved.get("id")
        if not reserved_id:
            raise ProviderError("Vultr did not return the new floating IP ID")
        await self._req("POST", f"/reserved-ips/{reserved_id}/attach",
                        json={"instance_id": str(server_id)})
        return reserved

    async def vultr_floating_ips(self, server_id):
        """List every Reserved IP currently attached to this Vultr instance."""
        if self.provider != "vultr":
            raise ProviderError("floating IP is only available for Vultr")
        data = await self._req("GET", "/reserved-ips?per_page=500")
        return [ip for ip in data.get("reserved_ips", [])
                if str(ip.get("instance_id")) == str(server_id)]

    async def vultr_floating_ip(self, reserved_ip_id):
        if self.provider != "vultr":
            raise ProviderError("floating IP is only available for Vultr")
        data = await self._req("GET", f"/reserved-ips/{reserved_ip_id}")
        return data.get("reserved_ip", data)

    async def delete_vultr_floating_ip(self, reserved_ip_id):
        """Permanently remove a Reserved IP (Vultr detaches it first)."""
        if self.provider != "vultr":
            raise ProviderError("floating IP is only available for Vultr")
        await self._req("DELETE", f"/reserved-ips/{reserved_ip_id}")

    async def vultr_power(self, server_id, action):
        """Start, halt, or reboot a Vultr instance."""
        if self.provider != "vultr":
            raise ProviderError("power controls are only available for Vultr")
        if action not in ("start", "halt", "reboot"):
            raise ProviderError("unsupported Vultr power action")
        await self._req("POST", f"/instances/{server_id}/{action}")
