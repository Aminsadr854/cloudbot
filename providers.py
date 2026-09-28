"""
Linode and Vultr, behind one interface.

Every request goes through the account's own proxy when it has one, because the
accounts may sit in different countries and a provider can refuse or mis-geo a
call that arrives from the wrong place. The proxy is given as
host:port:user:pass and turned into an authenticated HTTP proxy here.

Only the operations exposed by the bot are implemented. Provider clients are
created per request so token and proxy changes take effect immediately; the bot
keeps its own short-lived server/IP snapshot for chat lookups.
"""
import asyncio
import ipaddress
import logging
import socket
import time
from datetime import date

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


# -- in-memory cache for regions and plans ----------------------------------
CACHE_TTL_REGIONS = 3600  # 1 hour
CACHE_TTL_PLANS = 3600    # 1 hour

_CACHE: dict[tuple, tuple[float, any]] = {}


def clear_cache(provider: str | None = None):
    """Clear in-memory cache, optionally filtered by provider."""
    global _CACHE
    if provider is None:
        _CACHE.clear()
    else:
        _CACHE = {k: v for k, v in _CACHE.items() if k[0] != provider}


def _get_cached(key: tuple) -> any:
    now = time.time()
    if key in _CACHE:
        expire_at, data = _CACHE[key]
        if now < expire_at:
            return data
        del _CACHE[key]
    return None


def _set_cached(key: tuple, data: any, ttl: int = 3600):
    _CACHE[key] = (time.time() + ttl, data)


def get_cached_regions(provider: str, account_id=None) -> list | None:
    """Return cached region choices for a provider if available."""
    if provider == "linode":
        return _get_cached((provider, "regions", str(account_id or "")))
    return _get_cached((provider, "regions"))


def get_cached_plans(provider: str, region: str | None = None) -> list | None:
    """Return cached plan choices for a provider and region if available."""
    return _get_cached((provider, "plans", str(region or "")))


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
        self.account = account
        self.acc = account
        self.provider = account["provider"]
        self.token = account["token"]
        self.proxy = proxy_url(account.get("proxy"))
        self.proxy_family = account.get("proxy_family", "default")
        self.auto_backup = account.get("auto_backup", "disabled")

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
            rows = []
            page = 1
            while True:
                d = await self._req("GET", f"/linode/instances?page_size=500&page={page}")
                current = d.get("data", [])
                rows.extend(current)
                if page >= int(d.get("pages") or 1) or not current:
                    break
                page += 1
            out = []
            for i in rows:
                ips = [ip for ip in (i.get("ipv4") or []) if ip]
                out.append({
                    "id": i["id"], "label": i.get("label"),
                    "region": i.get("region"),
                    "country": region_country(self.provider, i.get("region")),
                    "ip": ips[0] if ips else None, "ips": ips,
                    "status": i.get("status"),
                    "plan": i.get("type"),
                })
            return out
        if self.provider == "vultr":
            rows = []
            page = 1
            while True:
                d = await self._req("GET", f"/instances?per_page=500&page={page}")
                current = d.get("instances", [])
                rows.extend(current)
                meta = d.get("meta") or {}
                pages = meta.get("total_pages") or meta.get("last_page")
                if not current or (pages is not None and page >= int(pages)):
                    break
                if pages is None and len(current) < 500:
                    break
                page += 1
            out = []
            for i in rows:
                main_ip = i.get("main_ip")
                ips = [main_ip] if main_ip and main_ip != "0.0.0.0" else []
                out.append({
                    "id": i["id"], "label": i.get("label") or i.get("hostname"),
                    "region": i.get("region"),
                    "country": region_country(self.provider, i.get("region")),
                    "ip": main_ip if ips else "(provisioning)", "ips": ips,
                    "status": i.get("status") + "/" + i.get("power_status", ""),
                    "plan": i.get("plan"),
                })
            return out
        # hetzner
        rows = []
        page = 1
        while True:
            d = await self._req("GET", f"/servers?per_page=50&page={page}")
            rows.extend(d.get("servers", []))
            pagination = (d.get("meta") or {}).get("pagination") or {}
            last_page = pagination.get("last_page")
            if last_page is not None and page >= int(last_page):
                break
            if not d.get("servers") or (last_page is None and len(d["servers"]) < 50):
                break
            page += 1
        out = []
        for i in rows:
            location = i.get("location") or (i.get("datacenter") or {}).get("location") or {}
            public_net = i.get("public_net") or {}
            ipv4 = (public_net.get("ipv4") or {}).get("ip")
            ipv6 = (public_net.get("ipv6") or {}).get("ip")
            ips = [ip for ip in (ipv4, ipv6) if ip]
            out.append({
                "id": i["id"], "label": i.get("name"),
                "region": location.get("name"),
                "country": country_code(location.get("country_iso") or location.get("country"))
                           or region_country(self.provider, location.get("name")),
                "ip": ipv4 or ipv6 or "(provisioning)", "ips": ips,
                "ipv4": ipv4, "ipv6": ipv6,
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
                    "plan": i.get("plan"), "default_password": i.get("default_password"),
                    "features": i.get("features", [])}
        # hetzner
        d = await self._req("GET", f"/servers/{server_id}")
        i = d.get("server", d)
        location = i.get("location") or (i.get("datacenter") or {}).get("location") or {}
        public_net = i.get("public_net") or {}
        ipv4 = (public_net.get("ipv4") or {}).get("ip")
        ipv6 = (public_net.get("ipv6") or {}).get("ip")
        ips = [ip for ip in (ipv4, ipv6) if ip]
        return {"id": i["id"], "label": i.get("name"),
                "region": location.get("name"),
                "country": country_code(location.get("country_iso") or location.get("country"))
                           or region_country(self.provider, location.get("name")),
                "ip": ipv4 or ipv6, "ips": ips, "ipv4": ipv4, "ipv6": ipv6,
                "status": i.get("status"),
                "plan": (i.get("server_type") or {}).get("name")}

    # -- choices for creation --------------------------------------------
    async def regions(self, force: bool = False, ttl: int = CACHE_TTL_REGIONS):
        account_id = str(self.account.get("id") or "")
        cache_key = ((self.provider, "regions", account_id)
                     if self.provider == "linode" else (self.provider, "regions"))
        if not force:
            cached = _get_cached(cache_key)
            if cached is not None:
                return cached

        if self.provider == "linode":
            d = await self._req("GET", "/regions?page_size=200")
            types = await self._linode_types(force=force)
            try:
                availability = await self._req("GET", "/account/availability?page_size=500")
                service_by_region = {
                    row.get("region"): row for row in availability.get("data", [])
                    if row.get("region")
                }
            except Exception:
                # Restricted tokens may not be able to read account availability.
                service_by_region = {}

            res = []
            for r in d.get("data", []):
                region_id = r["id"]
                service = service_by_region.get(region_id)
                linodes_allowed = (
                    "Linodes" in (service.get("available") or [])
                    if service is not None
                    else "Linodes" in (r.get("capabilities") or [])
                )
                count = len(types) if linodes_allowed else 0
                label = location_text(self.provider, r.get("label") or region_id,
                                      r.get("country"))
                label += (f" · {count} plans listed" if linodes_allowed
                          else " · 0 plans (Linodes unavailable)")
                res.append((region_id, label))
        elif self.provider == "vultr":
            d = await self._req("GET", "/regions?per_page=200")
            res = [(r["id"], location_text(
                        self.provider,
                        f"{r.get('city','')} {r.get('country','')}".strip() or r["id"],
                        r.get("country")))
                   for r in d.get("regions", [])]
        else:
            # Hetzner exposes per-location support and current availability on
            # each Server Type. Locations alone includes places where none of
            # the account's plans can currently be ordered.
            d, server_types = await asyncio.gather(
                self._req("GET", "/locations?per_page=50"),
                self._hetzner_server_types(force=force, ttl=ttl),
            )
            available_counts = {}
            for server_type in server_types:
                if (server_type.get("deprecated")
                        or self._hetzner_deprecation_expired(
                            server_type.get("deprecation"))):
                    continue
                for location in server_type.get("locations") or []:
                    name = str(location.get("name") or "")
                    if (name and location.get("available") is True
                            and not self._hetzner_deprecation_expired(
                                location.get("deprecation"))
                            and self._hetzner_price_for_location(server_type, name) is not None):
                        available_counts[name] = available_counts.get(name, 0) + 1
            res = []
            for location in d.get("locations", []):
                name = location.get("name")
                count = available_counts.get(str(name), 0)
                if not name or not count:
                    continue
                place = f"{location.get('city','')} {location.get('country','')}".strip() or name
                label = location_text(
                    self.provider, place,
                    location.get("country_iso") or location.get("country"))
                res.append((name, f"{label} · {count} available plans"))

        _set_cached(cache_key, res, ttl)
        return res

    async def _linode_types(self, force: bool = False):
        """Load the Linode type catalog once for region and plan choices."""
        cache_key = (self.provider, "linode-types")
        if not force:
            cached = _get_cached(cache_key)
            if cached is not None:
                return cached
        d = await self._req("GET", "/linode/types?page_size=500")
        types = d.get("data", [])
        _set_cached(cache_key, types, CACHE_TTL_PLANS)
        return types

    async def _hetzner_server_types(self, force: bool = False,
                                    ttl: int = CACHE_TTL_PLANS):
        """Return Hetzner's per-location support and current availability data."""
        cache_key = (self.provider, "server-types", str(self.account.get("id") or ""))
        if not force:
            cached = _get_cached(cache_key)
            if cached is not None:
                return cached
        data = await self._req("GET", "/server_types?per_page=100")
        server_types = data.get("server_types", [])
        _set_cached(cache_key, server_types, ttl)
        return server_types

    @staticmethod
    def _hetzner_location_entry(server_type, region):
        region = str(region or "")
        return next((location for location in server_type.get("locations") or []
                     if region in (str(location.get("name") or ""),
                                   str(location.get("id") or ""))), None)

    @staticmethod
    def _hetzner_deprecation_expired(deprecation):
        if not isinstance(deprecation, dict):
            return False
        unavailable_after = str(deprecation.get("unavailable_after") or "")[:10]
        if not unavailable_after:
            return False
        try:
            return date.fromisoformat(unavailable_after) <= date.today()
        except ValueError:
            return False

    @staticmethod
    def _hetzner_price_for_location(server_type, region):
        price = next((item for item in server_type.get("prices") or []
                      if str(item.get("location") or "") == str(region or "")), None)
        if not price:
            return None
        return (price.get("price_monthly") or {}).get("gross")

    async def plans(self, region=None, force: bool = False, ttl: int = CACHE_TTL_PLANS):
        cache_key = (self.provider, "plans", str(region or ""))
        if not force:
            cached = _get_cached(cache_key)
            if cached is not None:
                return cached

        if self.provider == "linode":
            types = await self._linode_types(force=force)
            out = []
            for t in types:
                region_prices = t.get("region_prices") or []
                price = (t.get("price") or {}).get("monthly")
                if region:
                    price = next((p.get("monthly") for p in region_prices
                                  if p.get("id") == region), price)
                transfer = t.get("transfer")
                traffic = f" · 📡 {transfer} GB traffic" if transfer is not None else ""
                out.append((t["id"],
                            f"{t.get('label', t['id'])}{traffic} - ${price}/mo"))
            res = out
        elif self.provider == "vultr":
            d = await self._req("GET", "/plans?per_page=500")
            avail_set = None
            if region:
                try:
                    avail_data = await self._req("GET", f"/regions/{region}/availability")
                    avail_set = set(avail_data.get("available_plans", []))
                except Exception:
                    pass
            out = []
            for p in d.get("plans", []):
                pid = p.get("id")
                if region:
                    if avail_set is not None:
                        if pid not in avail_set:
                            continue
                    elif region not in p.get("locations", []):
                        continue
                out.append((p["id"], f"{p.get('vcpu_count')}vCPU {p.get('ram')}MB "
                                     f"{p.get('disk')}GB - ${p.get('monthly_cost')}/mo"))
            res = out
        else:
            # Hetzner's per-location availability flag is the purchase filter.
            # Prices describe billing; they do not mean a type can be ordered there.
            server_types = await self._hetzner_server_types(force=force, ttl=ttl)
            out = []
            for t in server_types:
                if t.get("deprecated"):
                    continue
                location = self._hetzner_location_entry(t, region)
                if (not location or location.get("available") is not True
                        or self._hetzner_deprecation_expired(location.get("deprecation"))
                        or self._hetzner_deprecation_expired(t.get("deprecation"))):
                    continue
                monthly = self._hetzner_price_for_location(t, region)
                if monthly is None:
                    continue
                price = f" - €{float(monthly):.2f}/mo"
                out.append((t["name"], f"{t['name']} · {t.get('cores')}vCPU "
                                       f"{t.get('memory')}GB {t.get('disk')}GB{price}"))
            res = out

        _set_cached(cache_key, res, ttl)
        return res

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
    async def create_server(self, label, region, plan, image, root_password, auto_backup=None):
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
            backup_val = auto_backup or self.acc.get("auto_backup") or "disabled"
            body = {
                "label": label, "region": region, "plan": plan, "os_id": int(image),
                "hostname": label,
                "backups": backup_val,
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
        try:
            created = await self._req("POST", "/reserved-ips", json={
                "region": region, "ip_type": "v4", "label": label[:128],
            })
        except Exception as exc:
            raise ProviderError(f"Vultr Reserved-IP create request failed: {exc}") from exc
        reserved = created.get("reserved_ip", created)
        reserved_id = reserved.get("id")
        if not reserved_id:
            raise ProviderError("Vultr did not return the new floating IP ID")
        try:
            await self._req("POST", f"/reserved-ips/{reserved_id}/attach",
                            json={"instance_id": str(server_id)})
        except Exception as exc:
            address = reserved.get("ip") or reserved.get("ip_address") or reserved_id
            try:
                await self._req("DELETE", f"/reserved-ips/{reserved_id}")
            except Exception as cleanup_exc:
                raise ProviderError(
                    f"Vultr attach request failed after creating {address}; "
                    f"automatic cleanup also failed: {cleanup_exc}") from exc
            raise ProviderError(
                f"Vultr attach request failed; newly created Reserved IP {address} "
                f"was removed: {exc}") from exc
        return reserved

    async def vultr_floating_ips(self, server_id):
        """List every Reserved IP currently attached to this Vultr instance."""
        return [ip for ip in await self.vultr_reserved_ips()
                if str(ip.get("instance_id")) == str(server_id)]

    async def vultr_reserved_ips(self):
        """List all Vultr Reserved IPs so account caches need only one request."""
        if self.provider != "vultr":
            raise ProviderError("floating IP is only available for Vultr")
        rows = []
        page = 1
        while True:
            data = await self._req("GET", f"/reserved-ips?per_page=500&page={page}")
            current = data.get("reserved_ips", [])
            rows.extend(current)
            meta = data.get("meta") or {}
            pages = meta.get("total_pages") or meta.get("last_page")
            if not current or (pages is not None and page >= int(pages)):
                break
            if pages is None and len(current) < 500:
                break
            page += 1
        return rows

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

    async def set_vultr_backups(self, server_id, status="disabled"):
        """Enable or disable auto-backups on an existing Vultr instance."""
        if self.provider != "vultr":
            raise ProviderError("auto-backup toggle is only available for Vultr")
        if status not in ("disabled", "enabled"):
            raise ProviderError("backup status must be 'disabled' or 'enabled'")
        return await self._req("PATCH", f"/instances/{server_id}", json={"backups": status})

    # -- Hetzner Floating IPs -------------------------------------------
    async def hetzner_floating_ips(self, server_id=None):
        """List the Hetzner project Floating IPs, following every result page."""
        if self.provider != "hetzner":
            raise ProviderError("Hetzner Floating IPs are only available for Hetzner")
        rows = []
        page = 1
        while True:
            data = await self._req("GET", f"/floating_ips?per_page=50&page={page}")
            current = data.get("floating_ips", [])
            rows.extend(current)
            pagination = (data.get("meta") or {}).get("pagination") or {}
            last_page = pagination.get("last_page")
            if last_page is not None and page >= int(last_page):
                break
            if not current or (last_page is None and len(current) < 50):
                break
            page += 1
        if server_id is not None:
            return [row for row in rows if str(row.get("server")) == str(server_id)]
        return rows

    async def hetzner_floating_ip(self, floating_ip_id):
        if self.provider != "hetzner":
            raise ProviderError("Hetzner Floating IPs are only available for Hetzner")
        data = await self._req("GET", f"/floating_ips/{floating_ip_id}")
        return data.get("floating_ip", data)

    async def _wait_hetzner_action(self, result):
        action = result.get("action") or {}
        action_id = action.get("id")
        if not action_id:
            return action
        for attempt in range(60):
            if action.get("status") == "success":
                return action
            if action.get("status") == "error":
                error = action.get("error") or {}
                detail = error.get("message") if isinstance(error, dict) else str(error)
                raise ProviderError(f"Hetzner action failed: {detail or action.get('command')}")
            await asyncio.sleep(1)
            data = await self._req("GET", f"/actions/{action_id}")
            action = data.get("action", data)
        raise ProviderError(f"Hetzner action {action_id} did not finish within 60 seconds")

    async def create_hetzner_floating_ip(self, server_id, ip_type, name):
        """Create and assign a Hetzner IPv4 or IPv6 Floating IP."""
        if self.provider != "hetzner":
            raise ProviderError("Hetzner Floating IPs are only available for Hetzner")
        if ip_type not in ("ipv4", "ipv6"):
            raise ProviderError("Floating IP type must be ipv4 or ipv6")
        result = await self._req("POST", "/floating_ips", json={
            "type": ip_type, "server": int(server_id), "name": str(name)[:63],
        })
        floating = result.get("floating_ip", result)
        if result.get("action"):
            await self._wait_hetzner_action(result)
        return floating

    async def delete_hetzner_floating_ip(self, floating_ip_id):
        """Unassign and delete a Hetzner Floating IP after the caller confirms."""
        if self.provider != "hetzner":
            raise ProviderError("Hetzner Floating IPs are only available for Hetzner")
        floating = await self.hetzner_floating_ip(floating_ip_id)
        if (floating.get("protection") or {}).get("delete"):
            result = await self._req(
                "POST", f"/floating_ips/{floating_ip_id}/actions/change_protection",
                json={"delete": False})
            await self._wait_hetzner_action(result)
        if floating.get("server") is not None:
            result = await self._req(
                "POST", f"/floating_ips/{floating_ip_id}/actions/unassign")
            await self._wait_hetzner_action(result)
        await self._req("DELETE", f"/floating_ips/{floating_ip_id}")
        return True
