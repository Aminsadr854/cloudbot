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
import base64
import ipaddress
import logging
import secrets
import re
import socket
import time
import json
from datetime import date

import aiohttp
from yarl import URL
from proxy_pool import resolve_country, ProxyPoolError, components as parse_proxy, proxy_string

try:
    from aiohttp_socks import ProxyConnector
except Exception:  # pragma: no cover
    ProxyConnector = None

log = logging.getLogger("cloudbot.providers")

RETRYABLE_API_STATUS = {408, 425, 429, 500, 502, 503, 504}


def account_suspension(servers, info=None):
    """Promote explicit server suspension, never ordinary power-off or debt."""
    suspended = [s for s in servers
                 if str(s.get('status') or '').lower() == 'billing_suspension' or
                 'suspended' in re.split(r'[^a-z]+', str(s.get('status') or '').lower())]
    if not suspended:
        return {}
    reason = f"Account suspended: {len(suspended)} server(s) reported suspended by the provider."
    if any(str(s.get('status') or '').lower() == 'billing_suspension' for s in suspended):
        reason += " Billing suspension reported by the provider."
    if float((info or {}).get('owed') or 0) > 0:
        reason += " Outstanding billing balance; review the provider's billing page."
    return {"status": "suspended", "error": reason}


def _retry_after_seconds(response, attempt):
    """Respect Retry-After while keeping provider retries bounded."""
    value = response.headers.get("Retry-After") if response is not None else None
    try:
        if value is not None:
            return min(5.0, max(0.0, float(value)))
    except (TypeError, ValueError):
        pass
    return min(3.0, 0.35 * (2 ** (attempt - 1)) + ((attempt * 0.073) % 0.18))

LINODE = "https://api.linode.com/v4"
VULTR = "https://api.vultr.com/v2"
HETZNER = "https://api.hetzner.cloud/v1"
UPCLOUD = "https://api.upcloud.com/1.3"
CLOUDFERRO_IDENTITY = "https://keystone.cloudferro.com"
CLOUDFERRO_COMPUTE = "https://api.waw3-1.cloudferro.com:8774/v2.1"
CLOUDFERRO_IMAGE = "https://api.waw3-1.cloudferro.com:9292"
CLOUDFERRO_NETWORK = "https://api.waw3-1.cloudferro.com:9696"

# Capability flags are deliberately data, so callers can gate UI/actions
# without branching on provider names.  UpCloud injects keys through the
# server's login user-data and has no account-level SSH-key CRUD API.
PROVIDER_CAPABILITIES = {
    "linode": {"server_lifecycle": True, "public_ip": True, "floating_ip": False,
               "primary_ip_inventory": False, "networking": True,
               "local_ssh_injection": True, "ssh_key_crud": True},
    "vultr": {"server_lifecycle": True, "public_ip": True, "floating_ip": True,
              "primary_ip_inventory": False, "networking": True,
              "local_ssh_injection": True, "ssh_key_crud": True},
    "hetzner": {"server_lifecycle": True, "public_ip": True, "floating_ip": True,
                "primary_ip_inventory": True, "networking": True,
                "local_ssh_injection": True, "ssh_key_crud": True},
    "upcloud": {"server_lifecycle": True, "public_ip": True, "floating_ip": True,
                "primary_ip_inventory": False, "networking": True,
                "local_ssh_injection": True, "ssh_key_crud": False},
    "cloudferro": {"server_lifecycle": True, "public_ip": True, "floating_ip": True,
                    "primary_ip_inventory": False, "networking": True,
                    "local_ssh_injection": False, "ssh_key_crud": False},
}


def provider_capabilities(provider):
    """Return a stable copy of capability flags for a provider."""
    return dict(PROVIDER_CAPABILITIES.get(str(provider or "").lower(), {}))


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
    "cloudferro": {"waw3-1": "PL", "waw3": "PL"},
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
    try:
        return resolve_country(_COUNTRY_ALIASES.get(value, value))
    except ProxyPoolError:
        return None


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
CACHE_TTL_LINODE_REGIONS = 7 * 86400  # 7 days (Linode regions do not change)
CACHE_TTL_LINODE_PLANS = 7 * 86400    # 7 days

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
        if account_id:
            res = _get_cached((provider, "regions", str(account_id)))
            if res is not None:
                return res
        return _get_cached((provider, "regions", "")) or _get_cached((provider, "regions"))
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
    return proxy_string(parse_proxy(proxy))


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


def is_proxy_failure(error):
    """Only explicit proxy failures justify automatically changing an account route."""
    value = str(error)
    if 'provider traffic limit reached' in value.lower():
        return False
    if re.search(r"HTTP\s+407\b|Proxy authentication failed|ClientHttpProxyError|ClientProxyConnectionError|proxyconnect|tunnel\s+connection|could\s+not\s+connect\s+to\s+proxy|SOCKS proxy needs|Proxy(?:Connection|Timeout|Error)", value, re.I):
        return True
    if re.search(r"HTTP\s+\d{3}\b|invalid\s+(api\s+)?token|unauthori[sz]ed|authentication\s+failed|invalid\s+api\s+key|expired\s+token|permission denied", value, re.I):
        return False
    return bool(re.search(r"proxy|socks", value, re.I))


def sanitize_linode_label(label: str) -> str:
    """Linode labels must begin and end with an alphanumeric character and be 3-64 chars."""
    clean = re.sub(r"[^a-zA-Z0-9._-]+", "-", str(label).strip()).strip("-._")
    if not clean:
        clean = "linode-srv"
    if not clean[0].isalnum():
        clean = "s" + clean
    if not clean[-1].isalnum():
        clean = clean.rstrip("-._") + "1"
    if len(clean) < 3:
        clean = f"{clean}srv"
    return clean[:64]


def sanitize_upcloud_hostname(label: str) -> str:
    """Return a valid, bounded UpCloud hostname derived from a server title."""
    clean = re.sub(r"[^a-zA-Z0-9-]+", "-", str(label or "").strip().lower())
    clean = re.sub(r"-+", "-", clean).strip("-")
    if not clean:
        clean = "upcloud-server"
    if not clean[0].isalnum():
        clean = "upcloud-" + clean
    if not clean[-1].isalnum():
        clean = clean.rstrip("-") or "upcloud-server"
    return clean[:128].rstrip("-") or "upcloud-server"


from proxy_usage import ProxyUsage, TrafficLimitExceeded


class Provider:
    def __init__(self, account: dict):
        self.account = account
        self.acc = account
        self.provider = account["provider"]
        self.token = account["token"]
        self._cloudferro_token = None
        self.proxy = proxy_url(account.get("proxy"))
        self.proxy_family = account.get("proxy_family", "default")
        self.auto_backup = account.get("auto_backup", "disabled")

    def _base(self):
        return {"linode": LINODE, "vultr": VULTR, "hetzner": HETZNER,
                "upcloud": UPCLOUD, "cloudferro": CLOUDFERRO_COMPUTE}[self.provider]

    def _cloudferro_credentials(self):
        raw = self.token
        try:
            data = raw if isinstance(raw, dict) else json.loads(str(raw))
        except (TypeError, ValueError):
            parts = str(raw).split(":", 2)
            if len(parts) != 3:
                raise ProviderError("CloudFerro token must be JSON with id, secret, project_id")
            data = {"id": parts[0], "secret": parts[1], "project_id": parts[2]}
        cid = data.get("id") or data.get("application_credential_id")
        secret = data.get("secret") or data.get("application_credential_secret")
        project = data.get("project_id") or self.account.get("project_id")
        if not cid or not secret or not project:
            raise ProviderError("CloudFerro credentials require application credential id, secret, and project_id")
        return {"id": str(cid), "secret": str(secret), "project_id": str(project)}

    async def _cloudferro_auth(self):
        if self._cloudferro_token:
            return self._cloudferro_token
        c = self._cloudferro_credentials()
        # Keystone application credentials are already project-scoped. Sending
        # a separate project scope makes CloudFerro reject the request with
        # "Application credentials cannot request a scope".
        payload = {"auth": {"identity": {"methods": ["application_credential"],
                    "application_credential": {"id": c["id"], "secret": c["secret"]}}}}
        timeout = aiohttp.ClientTimeout(total=120, connect=45, sock_read=90)
        proxy = await proxy_for_family(self.proxy, self.proxy_family)
        meter = ProxyUsage(proxy)
        if proxy and proxy.startswith(("socks5", "socks4")):
            raise ProviderError("CloudFerro Keystone authentication requires an HTTP proxy")

        # Keystone authentication is always a POST. Retry only when an
        # explicit proxy is involved; authentication failures must not be
        # repeated as if this were a safe provider read.
        max_attempts = 4 if proxy else 1
        for attempt in range(1, max_attempts + 1):
            meter.ensure_available()
            try:
                async with aiohttp.ClientSession(timeout=timeout, trace_configs=meter.trace_configs()) as s:
                    async with s.post(CLOUDFERRO_IDENTITY + "/v3/auth/tokens", json=payload,
                                      proxy=proxy or None) as r:
                        text = await meter.text(r)
                        if r.status == 407:
                            raise ProviderError(f"HTTP 407: Proxy authentication failed ({text[:200]})")
                        if r.status >= 400:
                            raise ProviderError(self._safe_error_text(f"HTTP {r.status}: {text[:300]}"))
                        token = r.headers.get("X-Subject-Token")
                        if not token:
                            raise ProviderError("CloudFerro Keystone returned no token")
                        self._cloudferro_token = token
                        return token
            except ProviderError as pe:
                if proxy and ("407" in str(pe) or is_proxy_failure(pe)):
                    if attempt < max_attempts:
                        await asyncio.sleep(0.5 * attempt)
                        continue
                    safe_msg = self._safe_error_text(str(pe)[:250])
                    if safe_msg.lower().startswith("proxy failed"):
                        raise ProviderError(safe_msg)
                    raise ProviderError(f"Proxy failed: {safe_msg}")
                raise
            except Exception as e:
                is_p_err = False
                if proxy:
                    is_p_err = is_proxy_failure(e) or isinstance(e, (
                        aiohttp.ClientProxyConnectionError,
                        aiohttp.ClientHttpProxyError,
                        aiohttp.ClientConnectorError,
                        aiohttp.ServerDisconnectedError,
                        asyncio.TimeoutError,
                        TimeoutError,
                    ))
                    if not is_p_err:
                        val = str(e).lower()
                        if "proxy" in val or "socks" in val or "proxyconnect" in val:
                            is_p_err = True

                if is_p_err and attempt < max_attempts:
                    await asyncio.sleep(0.5 * attempt)
                    continue

                safe_msg = self._safe_error_text(f"{type(e).__name__}: {str(e)[:250]}")
                if is_p_err:
                    if safe_msg.lower().startswith("proxy failed"):
                        raise ProviderError(safe_msg)
                    raise ProviderError(f"Proxy failed: {safe_msg}")
                raise ProviderError(safe_msg)

    def _safe_error_text(self, value):
        text = str(value)
        for secret in (self.token, self.acc.get("proxy"), self.proxy):
            if secret:
                text = text.replace(str(secret), "[redacted]")
        return text

    async def _req(self, method, path, **kw):
        if self.provider == "cloudferro":
            headers = {"X-Auth-Token": await self._cloudferro_auth(),
                       "Content-Type": "application/json"}
        else:
            headers = {"Authorization": f"Bearer {self.token}",
                       "Content-Type": "application/json"}
        timeout = aiohttp.ClientTimeout(total=120, connect=45, sock_read=90)
        if self.provider == "cloudferro" and path.startswith("/v2/images"):
            url = CLOUDFERRO_IMAGE + path
        elif self.provider == "cloudferro" and path.startswith("/v2.0"):
            url = CLOUDFERRO_NETWORK + path
        else:
            url = self._base() + path
        proxy = await proxy_for_family(self.proxy, self.proxy_family)
        meter = ProxyUsage(proxy)
        is_socks = bool(proxy) and proxy.startswith(("socks5", "socks4"))
        safe_read = method.upper() in {"GET", "HEAD", "OPTIONS"}

        max_attempts = 4 if proxy else 1
        for attempt in range(1, max_attempts + 1):
            meter.ensure_available()
            try:
                if is_socks:
                    # A SOCKS proxy cannot be passed as aiohttp's proxy= (that is
                    # HTTP-proxy only); it has to be the session's connector.
                    if ProxyConnector is None:
                        raise ProviderError("SOCKS proxy needs aiohttp-socks installed")
                    conn = ProxyConnector.from_url(proxy)
                    async with aiohttp.ClientSession(timeout=timeout, connector=conn, trace_configs=meter.trace_configs()) as s:
                        async with s.request(method, url, headers=headers, **kw) as r:
                            text = await meter.text(r)
                            if r.status == 407:
                                raise ProviderError(f"HTTP 407: Proxy authentication failed ({text[:200]})")
                            if r.status >= 400:
                                if safe_read and r.status in RETRYABLE_API_STATUS and attempt < max_attempts:
                                    await asyncio.sleep(_retry_after_seconds(r, attempt))
                                    continue
                                raise ProviderError(self._safe_error_text(f"HTTP {r.status}: {text[:300]}"))
                            return await r.json() if text.strip() else {}
                else:
                    async with aiohttp.ClientSession(timeout=timeout, trace_configs=meter.trace_configs()) as s:
                        async with s.request(method, url, headers=headers,
                                             proxy=proxy or None, **kw) as r:
                            text = await meter.text(r)
                            if r.status == 407:
                                raise ProviderError(f"HTTP 407: Proxy authentication failed ({text[:200]})")
                            if r.status >= 400:
                                if safe_read and r.status in RETRYABLE_API_STATUS and attempt < max_attempts:
                                    await asyncio.sleep(_retry_after_seconds(r, attempt))
                                    continue
                                raise ProviderError(self._safe_error_text(f"HTTP {r.status}: {text[:300]}"))
                            return await r.json() if text.strip() else {}
            except ProviderError as pe:
                if proxy and ("407" in str(pe) or is_proxy_failure(pe)):
                    if attempt < max_attempts:
                        log.warning("request %s %s provider=%s proxy auth error (attempt %d/%d, retrying): %s",
                                    method, path, self.provider, attempt, max_attempts, str(pe))
                        await asyncio.sleep(0.5 * attempt)
                        continue
                    safe_msg = self._safe_error_text(str(pe)[:250])
                    if safe_msg.lower().startswith("proxy failed"):
                        raise ProviderError(safe_msg)
                    raise ProviderError(f"Proxy failed: {safe_msg}")
                raise
            except Exception as e:
                is_p_err = False
                if proxy:
                    is_p_err = is_proxy_failure(e) or isinstance(e, (
                        aiohttp.ClientProxyConnectionError,
                        aiohttp.ClientHttpProxyError,
                        aiohttp.ClientConnectorError,
                        aiohttp.ServerDisconnectedError,
                        asyncio.TimeoutError,
                        TimeoutError,
                    ))
                    if not is_p_err:
                        val = str(e).lower()
                        if "proxy" in val or "socks" in val or "proxyconnect" in val:
                            is_p_err = True

                if is_p_err and attempt < max_attempts:
                    log.warning("request %s %s provider=%s failed via proxy (attempt %d/%d, retrying): %s",
                                method, path, self.provider, attempt, max_attempts, type(e).__name__)
                    await asyncio.sleep(0.5 * attempt)
                    continue

                log.warning("request %s %s provider=%s failed (%s)",
                            method, path, self.provider, type(e).__name__)
                safe_msg = self._safe_error_text(f"{type(e).__name__}: {str(e)[:250]}")
                if is_p_err:
                    if safe_msg.lower().startswith("proxy failed"):
                        raise ProviderError(safe_msg)
                    raise ProviderError(f"Proxy failed: {safe_msg}")
                raise ProviderError(safe_msg)

    # -- connectivity check (also validates token + proxy together) ------
    async def whoami(self):
        if self.provider == "linode":
            d = await self._req("GET", "/profile")
            return d.get("username") or d.get("email") or "linode account"
        if self.provider == "vultr":
            d = await self._req("GET", "/account")
            acc = d.get("account", d)
            return acc.get("email") or acc.get("name") or "vultr account"
        if self.provider == "upcloud":
            d = await self._req("GET", "/account")
            acc = d.get("account", d)
            return acc.get("username") or acc.get("email") or "UpCloud account"
        if self.provider == "cloudferro":
            await self._req("GET", "/servers/detail?limit=1")
            return "CloudFerro project"
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
        if self.provider == "hetzner":
            try:
                d = await self._req("GET", "/servers")
                servers = d.get("servers", [])
                monthly_total = 0.0
                hourly_total = 0.0
                for s in servers:
                    st = s.get("server_type", {})
                    prices = st.get("prices", [])
                    if prices:
                        p_mo = prices[0].get("price_monthly", {}).get("gross") or prices[0].get("price_monthly", {}).get("net") or 0.0
                        p_hr = prices[0].get("price_hourly", {}).get("gross") or prices[0].get("price_hourly", {}).get("net") or 0.0
                        monthly_total += float(p_mo)
                        hourly_total += float(p_hr)
                return {
                    "name": "Hetzner Cloud Project",
                    "currency": "EUR",
                    "balance": round(monthly_total, 2),
                    "credit": 0.0,
                    "owed": 0.0,
                    "pending_charges": round(monthly_total, 2),
                    "net": -round(monthly_total, 2),
                    "monthly_runrate": round(monthly_total, 2),
                    "hourly_runrate": round(hourly_total, 4),
                    "servers_count": len(servers),
                }
            except Exception as e:
                log.warning("Hetzner account_info calculation failed: %s", e)
                return {
                    "name": "Hetzner Cloud Project",
                    "currency": "EUR",
                    "balance": 0.0,
                    "credit": 0.0,
                    "owed": 0.0,
                    "pending_charges": 0.0,
                    "net": 0.0,
                }
        if self.provider == "upcloud":
            d = await self._req("GET", "/account")
            acc = d.get("account", d)
            credits = acc.get("credits")
            try:
                credits = float(credits) if credits is not None else None
            except (TypeError, ValueError):
                credits = None
            return {"name": acc.get("username") or acc.get("company"),
                    "email": acc.get("email"), "balance": None,
                    "credit": credits, "owed": None,
                    "pending_charges": None, "net": None}
        if self.provider == "cloudferro":
            return {"name": "CloudFerro project", "currency": "EUR", "balance": None,
                    "credit": None, "owed": None, "pending_charges": None, "net": None}
        return None

    @staticmethod
    def _upcloud_server_summary(server):
        """Normalize an UpCloud server while preserving UUIDs as strings."""
        server = server or {}
        sid = str(server.get("uuid") or server.get("id") or "")
        ips = []
        ipv4 = ipv6 = None
        networking = server.get("ip_addresses") or server.get("networking") or {}
        raw_ips = networking.get("ip_address", []) if isinstance(networking, dict) else []
        if not raw_ips and isinstance(networking, dict):
            raw_ips = networking.get("ip_addresses", [])
        if isinstance(raw_ips, dict):
            raw_ips = [raw_ips]
        for item in raw_ips:
            if not isinstance(item, dict):
                continue
            address = item.get("address") or item.get("ip")
            if not address or str(item.get("access", "public")).lower() != "public":
                continue
            address = str(address)
            ips.append(address)
            if ":" in address and ipv6 is None:
                ipv6 = address
            elif ":" not in address and ipv4 is None:
                ipv4 = address
        region = server.get("zone") or server.get("zone_code") or server.get("region")
        plan = server.get("plan")
        if isinstance(plan, dict):
            plan = plan.get("name") or plan.get("id")
        return {"id": sid, "label": server.get("title") or server.get("hostname"),
                "region": region, "country": region_country("upcloud", region),
                "ip": ipv4 or ipv6, "ips": ips,
                "ipv4": ipv4, "ipv6": ipv6, "status": server.get("state") or server.get("status"),
                "plan": plan, "specs": server.get("plan_info") or {}}

    @staticmethod
    def _cloudferro_server_summary(server):
        addresses = server.get("addresses") or {}
        ips = []
        for network in addresses.values() if isinstance(addresses, dict) else []:
            rows = network if isinstance(network, list) else [network]
            for row in rows:
                if isinstance(row, dict) and row.get("addr"):
                    ips.append(str(row["addr"]))
        ipv4 = next((x for x in ips if ":" not in x), None)
        ipv6 = next((x for x in ips if ":" in x), None)
        return {"id": str(server.get("id") or ""), "label": server.get("name"),
                "region": "waw3-1", "country": "PL", "ip": ipv4 or ipv6,
                "ips": ips, "ipv4": ipv4, "ipv6": ipv6,
                "status": server.get("status"), "plan": str(server.get("flavor", {}).get("id")
                if isinstance(server.get("flavor"), dict) else server.get("flavor") or "")}

    def _cloudferro_project_id(self):
        return self._cloudferro_credentials()["project_id"]

    async def cloudferro_resource_limits(self):
        """Return OpenStack quotas together with current server/IP usage."""
        if self.provider != "cloudferro":
            raise ProviderError("resource limits are only implemented for CloudFerro")
        limits = await self._req("GET", "/limits")
        try:
            quotas = await self._req("GET", f"/v2.0/quotas/{self._cloudferro_project_id()}")
        except ProviderError:
            quotas = {}
        servers = await self.list_servers()
        fips = await self.cloudferro_floating_ips()
        absolute = ((limits.get("limits") or {}).get("absolute") or {})
        quota = (quotas.get("quota") or {}) if isinstance(quotas, dict) else {}
        # Neutron owns floating-IP quota. Nova often reports
        # ``maxTotalFloatingIps=-1`` and ``totalFloatingIpsUsed=0`` even when
        # Neutron has assigned addresses, so expose the authoritative values.
        absolute = dict(absolute)
        if quota.get("floatingip") is not None and int(quota["floatingip"]) >= 0:
            absolute["maxTotalFloatingIps"] = int(quota["floatingip"])
        absolute["totalFloatingIpsUsed"] = len(fips)
        return {"provider": "cloudferro", "project_id": self._cloudferro_project_id(),
                "limits": absolute, "quotas": quota,
                "usage": {"servers": len(servers), "floating_ips": len(fips)}}

    async def _cloudferro_server_ports(self, server_id):
        data = await self._req("GET", f"/servers/{server_id}/os-interface")
        return [str(row.get("port_id")) for row in data.get("interfaceAttachments", [])
                if row.get("port_id")]

    async def cloudferro_floating_ips(self, server_id=None):
        if self.provider != "cloudferro":
            raise ProviderError("floating IPs are only implemented for CloudFerro")
        data = await self._req("GET", "/v2.0/floatingips")
        rows = []
        wanted_ports = set(await self._cloudferro_server_ports(server_id)) if server_id else None
        port_servers = {}
        if server_id is None:
            for server in await self.list_servers():
                try:
                    for port in await self._cloudferro_server_ports(server["id"]):
                        port_servers[port] = str(server["id"])
                except ProviderError:
                    continue
        for row in (data.get("floatingips") or []):
            port_id = str(row.get("port_id")) if row.get("port_id") else None
            if wanted_ports is not None and port_id not in wanted_ports:
                continue
            rows.append({"id": row.get("id"), "ip": row.get("floating_ip_address"),
                         "type": "ipv6" if ":" in str(row.get("floating_ip_address") or "") else "ipv4",
                         "port_id": port_id, "server_id": str(server_id) if server_id and port_id else port_servers.get(port_id),
                         "network_id": row.get("floating_network_id"), "status": "assigned" if port_id else "unassigned"})
        return rows

    async def create_cloudferro_floating_ip(self, server_id=None):
        if self.provider != "cloudferro":
            raise ProviderError("floating IPs are only implemented for CloudFerro")
        nets = await self._req("GET", "/v2.0/networks?router:external=true")
        external = [n for n in nets.get("networks", []) if n.get("id")]
        if not external:
            raise ProviderError("CloudFerro has no external network available for floating IP allocation")
        body = {"floatingip": {"floating_network_id": external[0]["id"]}}
        result = await self._req("POST", "/v2.0/floatingips", json=body)
        row = result.get("floatingip", result)
        if server_id:
            await self.attach_cloudferro_floating_ip(row.get("id"), server_id)
            row["port_id"] = (await self._cloudferro_server_ports(server_id) or [None])[0]
        return {"id": row.get("id"), "ip": row.get("floating_ip_address"),
                "network_id": row.get("floating_network_id"), "port_id": row.get("port_id"),
                "server_id": str(server_id) if server_id else None,
                "type": "ipv6" if ":" in str(row.get("floating_ip_address") or "") else "ipv4"}

    async def attach_cloudferro_floating_ip(self, floating_id, server_id, port_id=None):
        ports = await self._cloudferro_server_ports(server_id)
        if port_id:
            target_port = str(port_id)
        else:
            assigned = {str(row.get("port_id")) for row in
                        await self.cloudferro_floating_ips(server_id)
                        if row.get("port_id")}
            target_port = next((port for port in ports if port not in assigned), None)
        if not target_port:
            # Neutron allows one floating IP per fixed address. Add another
            # interface on the server's project network for the next address.
            if not ports:
                raise ProviderError("CloudFerro server has no network port to attach a floating IP")
            port_data = await self._req("GET", f"/v2.0/ports/{ports[0]}")
            network_id = (port_data.get("port") or port_data).get("network_id")
            if not network_id:
                raise ProviderError("Could not determine the server network for a second floating IP")
            created = await self._req("POST", f"/servers/{server_id}/os-interface",
                                      json={"interfaceAttachment": {"net_id": network_id}})
            target_port = ((created.get("interfaceAttachment") or created).get("port_id"))
            if not target_port:
                raise ProviderError("CloudFerro did not return the new server interface")
        result = await self._req("PUT", f"/v2.0/floatingips/{floating_id}",
                                 json={"floatingip": {"port_id": target_port}})
        return result.get("floatingip", result)

    async def detach_cloudferro_floating_ip(self, floating_id):
        result = await self._req("PUT", f"/v2.0/floatingips/{floating_id}",
                                 json={"floatingip": {"port_id": None}})
        return result.get("floatingip", result)

    async def delete_cloudferro_floating_ip(self, floating_id):
        await self._req("DELETE", f"/v2.0/floatingips/{floating_id}")
        return True

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
                specs = i.get("specs") or {}
                out.append({
                    "id": i["id"], "label": i.get("label"),
                    "region": i.get("region"),
                    "country": region_country(self.provider, i.get("region")),
                    "ip": ips[0] if ips else None, "ips": ips,
                    "ipv4": ips, "ipv6": i.get("ipv6"),
                    "status": i.get("status"),
                    "plan": i.get("type"),
                    "specs": specs,
                    "ram": specs.get("memory"),
                    "disk": round(specs.get("disk", 0) / 1024) if specs.get("disk") else None,
                    "cores": specs.get("vcpus"),
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
        if self.provider == "upcloud":
            d = await self._req("GET", "/server")
            return [self._upcloud_server_summary(row)
                    for row in (d.get("servers") or {}).get("server", [])]
        if self.provider == "cloudferro":
            d = await self._req("GET", "/servers/detail?limit=100")
            return [self._cloudferro_server_summary(row) for row in d.get("servers", [])]
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
            ips = [ip for ip in (i.get("ipv4") or []) if ip]
            specs = i.get("specs") or {}
            return {"id": i["id"], "label": i.get("label"), "region": i.get("region"),
                    "country": region_country(self.provider, i.get("region")),
                    "ip": ips[0] if ips else None, "ips": ips,
                    "ipv4": ips, "ipv6": i.get("ipv6"),
                    "status": i.get("status"),
                    "plan": i.get("type"),
                    "specs": specs,
                    "ram": specs.get("memory"),
                    "disk": round(specs.get("disk", 0) / 1024) if specs.get("disk") else None,
                    "cores": specs.get("vcpus")}
        if self.provider == "vultr":
            d = await self._req("GET", f"/instances/{server_id}")
            i = d.get("instance", d)
            return {"id": i["id"], "label": i.get("label"), "region": i.get("region"),
                    "country": region_country(self.provider, i.get("region")),
                    "ip": i.get("main_ip"), "status": i.get("status"),
                    "plan": i.get("plan"), "default_password": i.get("default_password"),
                    "features": i.get("features", [])}
        if self.provider == "upcloud":
            d = await self._req("GET", f"/server/{server_id}")
            return self._upcloud_server_summary((d.get("server") or d))
        if self.provider == "cloudferro":
            d = await self._req("GET", f"/servers/{server_id}")
            return self._cloudferro_server_summary(d.get("server") or d)
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
            eff_ttl = ttl if ttl != CACHE_TTL_REGIONS else CACHE_TTL_LINODE_REGIONS
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
            _set_cached(cache_key, res, eff_ttl)
            if account_id:
                _set_cached((self.provider, "regions", ""), res, eff_ttl)
            self._precache_linode_plans_sync(types, res)
            return res
        elif self.provider == "vultr":
            d = await self._req("GET", "/regions?per_page=200")
            res = [(r["id"], location_text(
                        self.provider,
                        f"{r.get('city','')} {r.get('country','')}".strip() or r["id"],
                        r.get("country")))
                    for r in d.get("regions", [])]
        elif self.provider == "upcloud":
            d = await self._req("GET", "/zone")
            zones = (d.get("zones") or {}).get("zone", [])
            if isinstance(zones, dict):
                zones = [zones]
            res = []
            for zone in zones:
                if str(zone.get("public", "")).lower() not in ("true", "yes", "1"):
                    continue
                zid = str(zone.get("id") or zone.get("zone") or "")
                if not zid:
                    continue
                label = zone.get("title") or zone.get("description") or zid
                res.append((zid, location_text(self.provider, label,
                                                zone.get("country"))))
        elif self.provider == "cloudferro":
            res = [("waw3-1", "🇵🇱 Warsaw (CloudFerro WAW3-1)")]
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

    @staticmethod
    def _format_linode_plans(types, region=None):
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
        return out

    def _precache_linode_plans_sync(self, types, regions):
        default_plans = self._format_linode_plans(types, None)
        _set_cached((self.provider, "plans", ""), default_plans, CACHE_TTL_LINODE_PLANS)
        for r in regions:
            r_id = r[0] if isinstance(r, (list, tuple)) else str(r)
            plans_for_r = self._format_linode_plans(types, r_id)
            _set_cached((self.provider, "plans", r_id), plans_for_r, CACHE_TTL_LINODE_PLANS)

    async def precache_linode_plans(self, regions=None):
        if self.provider != "linode":
            return
        types = await self._linode_types(force=False)
        reg_list = regions
        if not reg_list:
            reg_list = get_cached_regions(self.provider, self.account.get("id")) or []
        self._precache_linode_plans_sync(types, reg_list)

    async def _linode_types(self, force: bool = False):
        """Load the Linode type catalog once for region and plan choices."""
        cache_key = (self.provider, "linode-types")
        if not force:
            cached = _get_cached(cache_key)
            if cached is not None:
                return cached
        d = await self._req("GET", "/linode/types?page_size=500")
        types = d.get("data", [])
        _set_cached(cache_key, types, CACHE_TTL_LINODE_PLANS)
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
            eff_ttl = ttl if ttl != CACHE_TTL_PLANS else CACHE_TTL_LINODE_PLANS
            types = await self._linode_types(force=force)
            res = self._format_linode_plans(types, region)
            _set_cached(cache_key, res, eff_ttl)
            return res
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
        elif self.provider == "upcloud":
            d = await self._req("GET", "/plan")
            plans = (d.get("plans") or {}).get("plan", [])
            if isinstance(plans, dict):
                plans = [plans]
            out = []
            for plan in plans:
                available = plan.get("available_zones") or plan.get("zones") or plan.get("zone_codes")
                if region and available and str(region) not in {str(x.get("id", x) if isinstance(x, dict) else x) for x in available}:
                    continue
                pid = str(plan.get("name") or plan.get("id") or "")
                if not pid:
                    continue
                cores = plan.get("core_number") or plan.get("cores")
                memory = plan.get("memory_amount") or plan.get("memory")
                storage = plan.get("storage_size") or plan.get("storage")
                price = plan.get("price") or plan.get("monthly_price")
                if isinstance(price, dict):
                    price = price.get("amount") or price.get("monthly")
                details = " · ".join(x for x in (f"{cores}vCPU" if cores else None,
                                                  f"{memory}MB" if memory else None,
                                                  f"{storage}GB" if storage else None) if x)
                label = plan.get("title") or pid
                out.append((pid, f"{label}{(' · ' + details) if details else ''}"
                            f"{(' - $' + str(price) + '/mo') if price is not None else ''}"))
            res = out
        elif self.provider == "cloudferro":
            d = await self._req("GET", "/flavors/detail?limit=100")
            res = []
            for flavor in d.get("flavors", []):
                fid = str(flavor.get("id") or "")
                if not fid:
                    continue
                res.append((fid, f"{flavor.get('name') or fid} · {flavor.get('vcpus', '?')}vCPU "
                            f"{flavor.get('ram', '?')}MB · {flavor.get('disk', '?')}GB"))
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

    async def images(self, region=None, force: bool = False, ttl: int = 86400):
        cache_key = (self.provider, "images", str(region or ""))
        if not force:
            cached = _get_cached(cache_key)
            if cached is not None:
                return cached
        if self.provider == "linode":
            d = await self._req("GET", "/images?page_size=500")
            imgs = [i for i in d.get("data", []) if i.get("is_public")]
            # Prefer the mainstream distributions; the full list is huge.
            pref = [i for i in imgs if any(x in i["id"] for x in
                    ("ubuntu22.04", "ubuntu24.04", "debian12", "debian11"))]
            chosen = pref or imgs
            res = [(i["id"], i.get("label") or i["id"]) for i in chosen[:40]]
            _set_cached(cache_key, res, ttl)
            return res
        if self.provider == "vultr":
            d = await self._req("GET", "/os?per_page=500")
            oss = d.get("os", [])
            pref = [o for o in oss if any(x in o.get("name", "").lower()
                    for x in ("ubuntu 22", "ubuntu 24", "debian 12", "debian 11"))]
            chosen = pref or oss
            res = [(str(o["id"]), o.get("name")) for o in chosen[:40]]
            _set_cached(cache_key, res, ttl)
            return res
        if self.provider == "upcloud":
            d = await self._req("GET", "/storage/template")
            storages = (d.get("storages") or {}).get("storage", [])
            if isinstance(storages, dict):
                storages = [storages]
            public = [s for s in storages
                      if str(s.get("access", "public")).lower() == "public"
                      and (not region or str(s.get("zone") or "") == str(region))]
            pref = [s for s in public if any(x in (s.get("title") or s.get("name") or "").lower()
                                              for x in ("ubuntu", "debian"))]
            chosen = pref or public
            res = [(str(s.get("uuid") or s.get("id")),
                    s.get("title") or s.get("name") or str(s.get("uuid") or s.get("id")))
                   for s in chosen[:40] if s.get("uuid") or s.get("id")]
            _set_cached(cache_key, res, ttl)
            return res
        if self.provider == "cloudferro":
            d = await self._req("GET", "/v2/images?status=active&visibility=public&limit=100")
            imgs = d.get("images", [])
            names = lambda i: (i.get("name") or "").lower()
            pref = [i for i in imgs if "ubuntu 22.04" in names(i) or "ubuntu-22.04" in names(i)]
            if not pref:
                pref = [i for i in imgs if "ubuntu 24.04" in names(i) or "ubuntu-24.04" in names(i)]
            if not pref:
                pref = [i for i in imgs if any(x in names(i) for x in ("ubuntu", "debian"))]
            chosen = pref or imgs
            res = [(str(i.get("id")), i.get("name") or str(i.get("id")))
                   for i in chosen[:40] if i.get("id")]
            _set_cached(cache_key, res, ttl)
            return res
        # hetzner system images; the image "name" (e.g. ubuntu-22.04) is what
        # create expects.
        d = await self._req("GET", "/images?type=system&per_page=100")
        imgs = d.get("images", [])
        pref = [i for i in imgs if any(x in (i.get("name") or "")
                for x in ("ubuntu-22.04", "ubuntu-24.04", "debian-12", "debian-11"))]
        chosen = pref or imgs
        res = [(i.get("name") or str(i["id"]),
                 i.get("description") or i.get("name")) for i in chosen[:40]]
        _set_cached(cache_key, res, ttl)
        return res

    # -- create ----------------------------------------------------------
    async def create_server(self, label, region, plan, image, root_password, auto_backup=None, ssh_keys=None, enable_ipv6=False):
        """Returns {id, ip, label, root_password, default_password?}."""
        if self.provider == "linode":
            clean_label = sanitize_linode_label(label)
            body = {
                "label": clean_label, "region": region, "type": plan, "image": image,
                "root_pass": root_password,
                "booted": True,
            }
            if ssh_keys:
                body["authorized_keys"] = [str(k) for k in ssh_keys if k]
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
            if ssh_keys:
                body["ssh_key_id"] = [str(k) for k in ssh_keys if k]
            d = await self._req("POST", "/instances", json=body)
            i = d.get("instance", d)
            # Vultr sets the root password itself and returns it once, on creation.
            return {"id": i["id"], "label": i.get("label"),
                    "ip": i.get("main_ip") if i.get("main_ip", "0.0.0.0") != "0.0.0.0" else None,
                    "region": i.get("region"), "plan": i.get("plan"),
                    "country": region_country(self.provider, i.get("region")),
                    "root_password": i.get("default_password") or root_password}
        if self.provider == "upcloud":
            # UpCloud creates from a public/private storage template by cloning
            # it into a new boot disk.  The operation is asynchronous and the
            # response contains the server in ``maintenance`` state.
            storage_device = {
                "action": "clone",
                "storage": str(image),
                "title": f"{label} operating system",
            }
            login_user = {"username": "root"}
            clean_keys = [str(key).strip() for key in (ssh_keys or []) if str(key).strip()]
            if clean_keys:
                # The JSON representation mirrors the API's repeated
                # ``ssh_key`` element from its XML schema.
                login_user["ssh_keys"] = {"ssh_key": clean_keys}
            body = {"server": {
                "title": str(label),
                "hostname": sanitize_upcloud_hostname(label),
                "zone": str(region),
                "plan": str(plan),
                "storage_devices": {"storage_device": [storage_device]},
                "login_user": login_user,
            }}
            d = await self._req("POST", "/server", json=body)
            server = d.get("server") or d
            normalized = self._upcloud_server_summary(server)
            # UpCloud only returns a generated one-time password for templates
            # that support password creation.  Never fall back to the caller's
            # generated secret: it was not sent to UpCloud and is unusable.
            password = (server.get("password") or server.get("root_password")
                        or d.get("password") or d.get("root_password"))
            if password:
                normalized["root_password"] = str(password)
            return normalized
        if self.provider == "cloudferro":
            networks = await self._req("GET", f"/v2.0/networks?project_id={self._cloudferro_project_id()}")
            project_networks = [n for n in networks.get("networks", [])
                                if n.get("id") and not n.get("router:external")]
            # A project may have several internal networks, but only the one
            # connected to its router can reach a public floating network.
            # Prefer a network seen on a project router; fall back to the
            # first project network for installations without router access.
            routed_ids = set()
            try:
                routers = await self._req("GET", "/v2.0/routers")
                for router in routers.get("routers", []):
                    if router.get("project_id") != self._cloudferro_project_id():
                        continue
                    ports = await self._req("GET", f"/v2.0/ports?device_id={router.get('id')}")
                    routed_ids.update(str(port.get("network_id")) for port in ports.get("ports", [])
                                      if port.get("network_id"))
            except ProviderError:
                pass
            selected_network = next((n for n in project_networks if str(n["id"]) in routed_ids),
                                    project_networks[0] if project_networks else None)
            body = {"server": {"name": str(label), "flavorRef": str(plan),
                                "imageRef": str(image), "adminPass": str(root_password),
                                "networks": [{"uuid": selected_network["id"]}] if selected_network else []}}
            clean_keys = [str(key).strip() for key in (ssh_keys or []) if str(key).strip()]
            if clean_keys:
                cloud_config = "#cloud-config\nssh_authorized_keys:\n" + "".join(
                    f"  - {key}\n" for key in clean_keys)
                body["server"]["user_data"] = base64.b64encode(
                    cloud_config.encode("utf-8")).decode("ascii")
            d = await self._req("POST", "/servers", json=body)
            normalized = self._cloudferro_server_summary(d.get("server") or d)
            normalized["root_password"] = root_password
            return normalized
        # hetzner: with no ssh_keys attached, Hetzner generates a root password
        # and returns it once in the create response - which is what node-it needs.
        body = {
            "name": label, "server_type": plan, "image": image,
            "location": region, "start_after_create": True,
            "public_net": {
                "enable_ipv4": True,
                "enable_ipv6": bool(enable_ipv6),
            },
        }
        if ssh_keys:
            body["ssh_keys"] = [k for k in ssh_keys if k]
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
        elif self.provider == "upcloud":
            sid = str(server_id)
            # UpCloud rejects deletion unless the server is stopped.  Read the
            # current state first and refuse to turn a destructive request into
            # an implicit power operation.
            current = await self._req("GET", f"/server/{sid}")
            server = current.get("server") or current
            state = str(server.get("state") or server.get("status") or "").lower()
            if state != "stopped":
                raise ProviderError("UpCloud server must be stopped before deletion")
            # Explicitly remove attached storages and their backups.  Leaving
            # either implicit would retain billable resources under API
            # defaults and makes the destructive operation ambiguous.
            await self._req("DELETE", f"/server/{sid}?storages=1&backups=delete")
            return True
        elif self.provider == "cloudferro":
            await self._req("DELETE", f"/servers/{server_id}")
            return True
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

    async def create_vultr_reserved_ip(self, region, ip_type="v4", label=""):
        """Create a Vultr Reserved IP without attaching it."""
        if self.provider != "vultr":
            raise ProviderError("floating IP is only available for Vultr")
        created = await self._req("POST", "/reserved-ips", json={
            "region": region, "ip_type": ip_type, "label": (label or "floating-ip")[:128],
        })
        return created.get("reserved_ip", created)

    async def attach_vultr_reserved_ip(self, reserved_ip_id, server_id):
        """Attach an existing Reserved IP to a Vultr instance."""
        if self.provider != "vultr":
            raise ProviderError("floating IP is only available for Vultr")
        return await self._req("POST", f"/reserved-ips/{reserved_ip_id}/attach",
                               json={"instance_id": str(server_id)})

    async def detach_vultr_reserved_ip(self, reserved_ip_id):
        """Detach a Reserved IP from its instance."""
        if self.provider != "vultr":
            raise ProviderError("floating IP is only available for Vultr")
        return await self._req("POST", f"/reserved-ips/{reserved_ip_id}/detach")

    async def vultr_power(self, server_id, action):
        """Start, halt, or reboot a Vultr instance."""
        if self.provider != "vultr":
            raise ProviderError("power controls are only available for Vultr")
        if action not in ("start", "halt", "reboot"):
            raise ProviderError("unsupported Vultr power action")
        await self._req("POST", f"/instances/{server_id}/{action}")

    async def linode_power(self, server_id, action):
        """Boot, shutdown, or reboot a Linode instance."""
        if self.provider != "linode":
            raise ProviderError("Linode power controls are only available for Linode")
        act = "boot" if action in ("start", "poweron", "boot") else action
        act = "shutdown" if act in ("shutdown", "poweroff", "halt") else act
        act = "reboot" if act == "reboot" else act
        if act not in ("boot", "shutdown", "reboot"):
            raise ProviderError(f"unsupported Linode power action: {action}")
        await self._req("POST", f"/linode/instances/{server_id}/{act}")

    async def linode_instance_ips(self, server_id):
        """Get full networking IP layout for a Linode instance."""
        if self.provider != "linode":
            raise ProviderError("Linode networking is only available for Linode accounts")
        return await self._req("GET", f"/linode/instances/{server_id}/ips")

    async def linode_swap_ips(self, linode_a_id, linode_b_id):
        """Swap IPv4 addresses between two Linodes in the same region."""
        if self.provider != "linode":
            raise ProviderError("Linode IP swap is only available for Linode")
        a = await self.server(linode_a_id)
        b = await self.server(linode_b_id)
        if a.get("region") != b.get("region"):
            raise ProviderError(f"Linodes must be in the same region to swap IPs ({a.get('region')} != {b.get('region')})")
        ip_a = a.get("ip")
        ip_b = b.get("ip")
        if not ip_a or not ip_b:
            raise ProviderError("Both Linodes must have an active IPv4 address to swap")
        payload = {
            "region": a["region"],
            "assignments": [
                {"address": ip_a, "linode_id": int(linode_b_id)},
                {"address": ip_b, "linode_id": int(linode_a_id)}
            ]
        }
        return await self._req("POST", "/networking/ips/assign", json=payload)

    async def apply_linode_promo_code(self, promo_code):
        """Apply a promotional credit code to the Linode account."""
        if self.provider != "linode":
            raise ProviderError("Promo codes are only supported for Linode accounts")
        promo_code = str(promo_code or "").strip()
        if not promo_code:
            raise ProviderError("Promo code is required")
        return await self._req("POST", "/account/promo-codes", json={"promo_code": promo_code})

    async def set_vultr_backups(self, server_id, status="disabled"):
        """Enable or disable auto-backups on an existing Vultr instance."""
        if self.provider != "vultr":
            raise ProviderError("auto-backup toggle is only available for Vultr")
        if status not in ("disabled", "enabled"):
            raise ProviderError("backup status must be 'disabled' or 'enabled'")
        return await self._req("PATCH", f"/instances/{server_id}", json={"backups": status})

    # -- UpCloud IPs and server networking ------------------------------
    @staticmethod
    def _upcloud_ip_row(raw):
        """Normalize an UpCloud IP object without coercing addresses/UUIDs."""
        raw = raw or {}
        family = str(raw.get("family") or "").strip().lower()
        floating = raw.get("floating")
        if isinstance(floating, str):
            floating = floating.lower() in {"yes", "true", "1"}
        else:
            floating = bool(floating)
        return {
            "address": str(raw.get("address") or ""),
            "family": family,
            "server_id": (str(raw.get("server") or raw.get("server_uuid"))
                          if (raw.get("server") or raw.get("server_uuid")) is not None else None),
            "zone": raw.get("zone"),
            "ptr": raw.get("ptr_record") or raw.get("ptr") or "",
            "floating": floating,
            "release_policy": raw.get("release_policy"),
        }

    @staticmethod
    def _upcloud_interfaces(payload):
        networking = (payload or {}).get("networking", payload or {})
        interfaces = networking.get("interfaces", networking.get("interface", [])) \
            if isinstance(networking, dict) else []
        if isinstance(interfaces, dict):
            interfaces = interfaces.get("interface", [])
        if isinstance(interfaces, dict):
            interfaces = [interfaces]
        return [item for item in interfaces if isinstance(item, dict)]

    async def _upcloud_stopped_server(self, server_id):
        sid = str(server_id or "").strip()
        if not sid:
            raise ProviderError("UpCloud server UUID is required")
        data = await self._req("GET", f"/server/{sid}")
        server = data.get("server", data) if isinstance(data, dict) else {}
        state = str(server.get("state") or server.get("status") or "").lower()
        if state != "stopped":
            raise ProviderError("UpCloud server must be stopped before changing its network")
        return server

    async def upcloud_networking(self, server_id):
        if self.provider != "upcloud":
            raise ProviderError("UpCloud networking is only available for UpCloud accounts")
        sid = str(server_id or "").strip()
        if not sid:
            raise ProviderError("UpCloud server UUID is required")
        data = await self._req("GET", f"/server/{sid}/networking")
        interfaces = self._upcloud_interfaces(data)
        normalized = []
        for iface in interfaces:
            copy = dict(iface)
            addresses = iface.get("ip_addresses") or iface.get("ip-addresses") or {}
            raw_ips = addresses.get("ip_address", []) if isinstance(addresses, dict) else addresses
            if isinstance(raw_ips, dict):
                raw_ips = [raw_ips]
            copy["ip_addresses"] = [self._upcloud_ip_row({**ip, "server": sid})
                                     for ip in (raw_ips or []) if isinstance(ip, dict)]
            normalized.append(copy)
        return {"server_id": sid, "interfaces": normalized}

    async def _upcloud_public_mac(self, server_id):
        network = await self.upcloud_networking(server_id)
        for iface in network.get("interfaces", []):
            kind = str(iface.get("type") or iface.get("network") or "").lower()
            if kind == "public" and iface.get("mac"):
                return str(iface["mac"])
        # Some responses omit interface type; a public address is still a
        # reliable indication that the interface is the public one.
        for iface in network.get("interfaces", []):
            if iface.get("mac") and any(row.get("family") in {"ipv4", "ipv6"}
                                        for row in iface.get("ip_addresses", [])):
                return str(iface["mac"])
        raise ProviderError("UpCloud server has no public network interface MAC")

    @staticmethod
    def _validate_upcloud_release_policy(policy):
        policy = str(policy or "").strip().lower()
        if policy not in {"keep", "release"}:
            raise ProviderError("UpCloud release_policy must be 'keep' or 'release'")
        return policy

    async def upcloud_ip_addresses(self, server_id=None):
        if self.provider != "upcloud":
            raise ProviderError("UpCloud IP addresses are only available for UpCloud accounts")
        data = await self._req("GET", "/ip_address")
        container = data.get("ip_addresses", data) if isinstance(data, dict) else {}
        raw = container.get("ip_address", []) if isinstance(container, dict) else container
        if isinstance(raw, dict):
            raw = [raw]
        rows = [self._upcloud_ip_row(item) for item in (raw or []) if isinstance(item, dict)]
        if server_id is not None:
            sid = str(server_id)
            rows = [row for row in rows if str(row.get("server_id")) == sid]
        return rows

    async def create_upcloud_floating_ip(self, server_id, zone, release_policy):
        if self.provider != "upcloud":
            raise ProviderError("UpCloud floating IPs are only available for UpCloud accounts")
        sid = str(server_id or "").strip()
        zone = str(zone or "").strip()
        if not sid or not zone:
            raise ProviderError("UpCloud server UUID and zone are required")
        policy = self._validate_upcloud_release_policy(release_policy)
        await self._upcloud_stopped_server(sid)
        mac = await self._upcloud_public_mac(sid)
        result = await self._req("POST", "/ip_address", json={"ip_address": {
            "access": "public", "family": "IPv4", "floating": "yes",
            "zone": zone, "server": sid, "mac": mac,
            "release_policy": policy,
        }})
        raw = result.get("ip_address", result) if isinstance(result, dict) else {}
        return self._upcloud_ip_row(raw)

    async def attach_upcloud_floating_ip(self, address, server_id):
        if self.provider != "upcloud":
            raise ProviderError("UpCloud floating IPs are only available for UpCloud accounts")
        address = str(address or "").strip()
        sid = str(server_id or "").strip()
        if not address or not sid:
            raise ProviderError("UpCloud IP address and server UUID are required")
        await self._upcloud_stopped_server(sid)
        mac = await self._upcloud_public_mac(sid)
        result = await self._req("PATCH", f"/ip_address/{address}",
                                 json={"ip_address": {"mac": mac}})
        raw = result.get("ip_address", result) if isinstance(result, dict) else {}
        return self._upcloud_ip_row(raw)

    async def detach_upcloud_floating_ip(self, address):
        if self.provider != "upcloud":
            raise ProviderError("UpCloud floating IPs are only available for UpCloud accounts")
        address = str(address or "").strip()
        if not address:
            raise ProviderError("UpCloud IP address is required")
        details = await self._req("GET", f"/ip_address/{address}")
        raw = details.get("ip_address", details) if isinstance(details, dict) else {}
        sid = raw.get("server") or raw.get("server_uuid")
        if sid:
            await self._upcloud_stopped_server(sid)
        result = await self._req("PATCH", f"/ip_address/{address}",
                                 json={"ip_address": {"mac": None}})
        raw_result = result.get("ip_address", result) if isinstance(result, dict) else {}
        return self._upcloud_ip_row(raw_result)

    async def update_upcloud_ip(self, address, ptr=None, release_policy=None):
        if self.provider != "upcloud":
            raise ProviderError("UpCloud IP addresses are only available for UpCloud accounts")
        address = str(address or "").strip()
        if not address:
            raise ProviderError("UpCloud IP address is required")
        body = {}
        if ptr is not None:
            body["ptr_record"] = str(ptr)
        if release_policy is not None:
            body["release_policy"] = self._validate_upcloud_release_policy(release_policy)
        if not body:
            raise ProviderError("PTR or release_policy is required")
        result = await self._req("PATCH", f"/ip_address/{address}",
                                 json={"ip_address": body})
        raw = result.get("ip_address", result) if isinstance(result, dict) else {}
        return self._upcloud_ip_row(raw)

    async def delete_upcloud_ip(self, address):
        if self.provider != "upcloud":
            raise ProviderError("UpCloud IP addresses are only available for UpCloud accounts")
        address = str(address or "").strip()
        if not address:
            raise ProviderError("UpCloud IP address is required")
        details = await self._req("GET", f"/ip_address/{address}")
        raw = details.get("ip_address", details) if isinstance(details, dict) else {}
        sid = raw.get("server") or raw.get("server_uuid")
        if sid:
            await self._upcloud_stopped_server(sid)
        await self._req("DELETE", f"/ip_address/{address}")
        return True

    async def add_upcloud_interface_ip(self, server_id, interface_index, address=None,
                                       family="IPv4", force=False):
        if self.provider != "upcloud":
            raise ProviderError("UpCloud networking is only available for UpCloud accounts")
        sid = str(server_id or "").strip()
        if not sid:
            raise ProviderError("UpCloud server UUID is required")
        await self._upcloud_stopped_server(sid)
        family = str(family or "").strip()
        if family not in {"IPv4", "IPv6"}:
            raise ProviderError("UpCloud IP family must be IPv4 or IPv6")
        body_ip = {"family": family}
        if address is not None and str(address).strip():
            body_ip["address"] = str(address).strip()
        path = f"/server/{sid}/networking/interface/{int(interface_index)}/ip_address"
        if force:
            path += "?force=yes"
        result = await self._req("POST", path, json={"ip_address": body_ip})
        raw = result.get("ip_address", result) if isinstance(result, dict) else {}
        return self._upcloud_ip_row({**raw, "server": sid})

    async def remove_upcloud_interface_ip(self, server_id, interface_index, address):
        if self.provider != "upcloud":
            raise ProviderError("UpCloud networking is only available for UpCloud accounts")
        sid = str(server_id or "").strip()
        address = str(address or "").strip()
        if not sid or not address:
            raise ProviderError("UpCloud server UUID and IP address are required")
        await self._upcloud_stopped_server(sid)
        return await self._req("DELETE", f"/server/{sid}/networking/interface/{int(interface_index)}/ip_address/{address}")

    # -- Hetzner Primary IPs --------------------------------------------
    def _primary_provider(self):
        if self.provider != "hetzner":
            raise ProviderError("Primary IPs are only available for Hetzner")

    async def hetzner_primary_ips(self):
        self._primary_provider()
        rows, page = [], 1
        while True:
            data = await self._req("GET", f"/primary_ips?per_page=50&page={page}")
            current = data.get("primary_ips", [])
            rows.extend(current)
            pagination = (data.get("meta") or {}).get("pagination") or {}
            next_page = pagination.get("next_page")
            if next_page:
                page = int(next_page)
            elif pagination or len(current) < 50:
                return rows
            else:
                page += 1

    async def hetzner_primary_ip(self, ip_id):
        self._primary_provider()
        data = await self._req("GET", f"/primary_ips/{int(ip_id)}")
        return data["primary_ip"]

    async def create_hetzner_primary_ip(self, location, ip_type, name):
        self._primary_provider()
        if ip_type not in ("ipv4", "ipv6"):
            raise ProviderError("Primary IP type must be ipv4 or ipv6")
        result = await self._req("POST", "/primary_ips", json={
            "location": location, "type": ip_type, "name": name,
            "assignee_type": "server", "auto_delete": False,
        })
        await self._wait_hetzner_action(result)
        return result["primary_ip"]

    async def update_hetzner_primary_ip(self, ip_id, **changes):
        self._primary_provider()
        if not changes or set(changes) - {"name", "auto_delete"}:
            raise ProviderError("Unsupported Primary IP update")
        data = await self._req("PUT", f"/primary_ips/{int(ip_id)}", json=changes)
        return data["primary_ip"]

    async def protect_hetzner_primary_ip(self, ip_id, enabled):
        self._primary_provider()
        await self._wait_hetzner_action(await self._req(
            "POST", f"/primary_ips/{int(ip_id)}/actions/change_protection",
            json={"delete": bool(enabled)}))

    async def _primary_server_off(self, server_id):
        data = await self._req("GET", f"/servers/{int(server_id)}")
        server = data["server"]
        if server.get("status") != "off":
            raise ProviderError("ابتدا سرور را خاموش کنید؛ تغییر Primary IP نیاز به خاموشی دارد.")
        return server

    async def unassign_hetzner_primary_ip(self, ip_id):
        ip = await self.hetzner_primary_ip(ip_id)
        if ip.get("assignee_id") is None:
            return
        await self._primary_server_off(ip["assignee_id"])
        await self._wait_hetzner_action(await self._req(
            "POST", f"/primary_ips/{int(ip_id)}/actions/unassign"))

    async def assign_hetzner_primary_ip(self, ip_id, server_id):
        """Replace the same-family IP, retaining the old allocation with rollback."""
        ip = await self.hetzner_primary_ip(ip_id)
        if ip.get("assignee_id") is not None:
            if str(ip["assignee_id"]) == str(server_id):
                return
            raise ProviderError("این IP به سرور دیگری متصل است؛ ابتدا آن را جدا کنید.")
        server = await self._primary_server_off(server_id)
        location = server.get("location") or (server.get("datacenter") or {}).get("location") or {}
        ip_location = ip.get("location") or (ip.get("datacenter") or {}).get("location") or {}
        if not location.get("name") or location.get("name") != ip_location.get("name"):
            raise ProviderError("IP و سرور باید در یک منطقه باشند.")
        old = (server.get("public_net", {}).get(ip["type"]) or {}).get("id")
        if old:
            await self.update_hetzner_primary_ip(old, auto_delete=False)
            await self.unassign_hetzner_primary_ip(old)
        try:
            await self._wait_hetzner_action(await self._req(
                "POST", f"/primary_ips/{int(ip_id)}/actions/assign",
                json={"assignee_type": "server", "assignee_id": int(server_id)}))
        except Exception as exc:
            if old:
                try:
                    # An action may have completed after its response was lost.
                    current = (await self._req("GET", f"/servers/{int(server_id)}"))["server"]
                    attached = (current.get("public_net", {}).get(ip["type"]) or {}).get("id")
                    if str(attached) == str(ip_id):
                        return
                    if attached:
                        raise ProviderError("Another IP is now attached; inspect the server")
                    await self._wait_hetzner_action(await self._req(
                        "POST", f"/primary_ips/{old}/actions/assign",
                        json={"assignee_type": "server", "assignee_id": int(server_id)}))
                except Exception as rollback:
                    raise ProviderError(f"Assign failed: {exc}; restore old IP {old} manually: {rollback}") from exc
                raise ProviderError(f"Assign failed; old IP {old} restored: {exc}") from exc
            raise

    async def delete_hetzner_primary_ip(self, ip_id):
        ip = await self.hetzner_primary_ip(ip_id)
        if ip.get("assignee_id") is not None:
            raise ProviderError("ابتدا IP را از سرور جدا کنید.")
        if (ip.get("protection") or {}).get("delete"):
            raise ProviderError("ابتدا محافظت حذف را غیرفعال کنید.")
        await self._req("DELETE", f"/primary_ips/{int(ip_id)}")

    async def hetzner_power(self, server_id, action):
        self._primary_provider()
        if action not in ("shutdown", "poweron", "reboot", "poweroff"):
            raise ProviderError(f"Unsupported power action: {action}")
        await self._wait_hetzner_action(await self._req(
            "POST", f"/servers/{int(server_id)}/actions/{action}"))

    async def power_server(self, server_id, action):
        """Unified power action across all supported providers (start, halt/shutdown, reboot)."""
        action = str(action).strip().lower()
        if self.provider == "vultr":
            v_action = "start" if action in ("start", "poweron", "boot") else action
            v_action = "halt" if v_action in ("halt", "poweroff", "shutdown") else v_action
            return await self.vultr_power(server_id, v_action)
        elif self.provider == "hetzner":
            h_action = "poweron" if action in ("start", "poweron", "boot") else action
            h_action = "shutdown" if h_action in ("shutdown", "halt") else h_action
            h_action = "poweroff" if h_action == "poweroff" else h_action
            h_action = "reboot" if h_action == "reboot" else h_action
            return await self.hetzner_power(server_id, h_action)
        elif self.provider == "linode":
            return await self.linode_power(server_id, action)
        elif self.provider == "upcloud":
            if action in ("start", "poweron", "boot"):
                endpoint = "start"
            elif action in ("halt", "shutdown", "poweroff", "stop"):
                endpoint = "stop"
            elif action == "reboot":
                endpoint = "restart"
            else:
                raise ProviderError(f"unsupported UpCloud power action: {action}")
            sid = str(server_id)
            if endpoint == "start":
                payload = {"server": {"start_type": "sync"}}
            elif endpoint == "stop":
                payload = {"stop_server": {"stop_type": "soft", "timeout": "60"}}
            else:
                payload = {"restart_server": {
                    "stop_type": "soft", "timeout": "60", "timeout_action": "destroy",
                }}
            await self._req("POST", f"/server/{sid}/{endpoint}", json=payload)
            return True
        elif self.provider == "cloudferro":
            if action in ("start", "poweron", "boot"):
                payload = {"os-start": None}
            elif action in ("halt", "shutdown", "poweroff", "stop"):
                payload = {"os-stop": None}
            elif action == "reboot":
                payload = {"reboot": {"type": "SOFT"}}
            else:
                raise ProviderError(f"unsupported CloudFerro power action: {action}")
            await self._req("POST", f"/servers/{server_id}/action", json=payload)
            return True
        raise ProviderError(f"power controls not supported for provider: {self.provider}")

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

    async def create_hetzner_floating_ip(self, server_id=None, ip_type="ipv4", name="", home_location=None):
        """Create and optionally assign a Hetzner IPv4 or IPv6 Floating IP."""
        if self.provider != "hetzner":
            raise ProviderError("Hetzner Floating IPs are only available for Hetzner")
        if ip_type not in ("ipv4", "ipv6"):
            raise ProviderError("Floating IP type must be ipv4 or ipv6")
        body = {
            "type": ip_type,
            "name": str(name)[:63] if name else f"fip-{secrets.token_hex(4)}",
        }
        if server_id is not None:
            body["server"] = int(server_id)
        if home_location is not None:
            body["home_location"] = str(home_location)
        result = await self._req("POST", "/floating_ips", json=body)
        floating = result.get("floating_ip", result)
        if result.get("action"):
            await self._wait_hetzner_action(result)
        return floating

    async def assign_hetzner_floating_ip(self, floating_ip_id, server_id):
        """Assign an existing Hetzner Floating IP to a server."""
        if self.provider != "hetzner":
            raise ProviderError("Hetzner Floating IPs are only available for Hetzner")
        result = await self._req(
            "POST", f"/floating_ips/{floating_ip_id}/actions/assign",
            json={"server": int(server_id)})
        return await self._wait_hetzner_action(result)

    async def unassign_hetzner_floating_ip(self, floating_ip_id):
        """Unassign an existing Hetzner Floating IP."""
        if self.provider != "hetzner":
            raise ProviderError("Hetzner Floating IPs are only available for Hetzner")
        result = await self._req("POST", f"/floating_ips/{floating_ip_id}/actions/unassign")
        return await self._wait_hetzner_action(result)

    async def change_hetzner_floating_ip_ptr(self, floating_ip_id, ip, dns_ptr):
        """Change PTR reverse DNS for a Hetzner Floating IP."""
        if self.provider != "hetzner":
            raise ProviderError("Hetzner Floating IPs are only available for Hetzner")
        result = await self._req(
            "POST", f"/floating_ips/{floating_ip_id}/actions/change_dns_ptr",
            json={"ip": ip, "dns_ptr": dns_ptr})
        return await self._wait_hetzner_action(result)

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

    # -- SSH Keys --------------------------------------------------------
    async def hetzner_ssh_keys(self):
        if self.provider != "hetzner":
            raise ProviderError("Hetzner SSH keys are only available for Hetzner")
        rows, page = [], 1
        while True:
            data = await self._req("GET", f"/ssh_keys?per_page=50&page={page}")
            current = data.get("ssh_keys", [])
            rows.extend(current)
            pagination = (data.get("meta") or {}).get("pagination") or {}
            last_page = pagination.get("last_page")
            if last_page is not None and page >= int(last_page):
                break
            if not current or (last_page is None and len(current) < 50):
                break
            page += 1
        return rows

    async def create_hetzner_ssh_key(self, name, public_key):
        if self.provider != "hetzner":
            raise ProviderError("Hetzner SSH keys are only available for Hetzner")
        data = await self._req("POST", "/ssh_keys", json={"name": str(name), "public_key": str(public_key).strip()})
        return data.get("ssh_key", data)

    async def delete_hetzner_ssh_key(self, ssh_key_id):
        if self.provider != "hetzner":
            raise ProviderError("Hetzner SSH keys are only available for Hetzner")
        await self._req("DELETE", f"/ssh_keys/{ssh_key_id}")
        return True

    async def linode_ssh_keys(self):
        if self.provider != "linode":
            raise ProviderError("Linode SSH keys are only available for Linode")
        data = await self._req("GET", "/profile/sshkeys")
        return data.get("data", [])

    async def create_linode_ssh_key(self, label, ssh_key):
        if self.provider != "linode":
            raise ProviderError("Linode SSH keys are only available for Linode")
        return await self._req("POST", "/profile/sshkeys", json={"label": str(label), "ssh_key": str(ssh_key).strip()})

    async def delete_linode_ssh_key(self, ssh_key_id):
        if self.provider != "linode":
            raise ProviderError("Linode SSH keys are only available for Linode")
        await self._req("DELETE", f"/profile/sshkeys/{ssh_key_id}")
        return True

    async def vultr_ssh_keys(self):
        if self.provider != "vultr":
            raise ProviderError("Vultr SSH keys are only available for Vultr")
        rows, page = [], 1
        while True:
            data = await self._req("GET", f"/ssh-keys?per_page=500&page={page}")
            current = data.get("ssh_keys", [])
            rows.extend(current)
            meta = data.get("meta") or {}
            pages = meta.get("total_pages") or meta.get("last_page")
            if not current or (pages is not None and page >= int(pages)):
                break
            if pages is None and len(current) < 500:
                break
            page += 1
        return rows

    async def create_vultr_ssh_key(self, name, ssh_key):
        if self.provider != "vultr":
            raise ProviderError("Vultr SSH keys are only available for Vultr")
        data = await self._req("POST", "/ssh-keys", json={"name": str(name), "ssh_key": str(ssh_key).strip()})
        return data.get("ssh_key", data)

    async def delete_vultr_ssh_key(self, ssh_key_id):
        if self.provider != "vultr":
            raise ProviderError("Vultr SSH keys are only available for Vultr")
        await self._req("DELETE", f"/ssh-keys/{ssh_key_id}")
        return True

    async def list_ssh_keys(self):
        """Unified SSH keys retrieval across accounts."""
        if self.provider == "hetzner":
            return await self.hetzner_ssh_keys()
        elif self.provider == "vultr":
            return await self.vultr_ssh_keys()
        elif self.provider == "linode":
            return await self.linode_ssh_keys()
        return []

    async def create_ssh_key(self, name, public_key):
        """Unified SSH key creation across accounts."""
        if self.provider == "hetzner":
            return await self.create_hetzner_ssh_key(name, public_key)
        elif self.provider == "vultr":
            return await self.create_vultr_ssh_key(name, public_key)
        elif self.provider == "linode":
            return await self.create_linode_ssh_key(name, public_key)
        raise ProviderError(f"SSH keys not supported for {self.provider}")

    async def delete_ssh_key(self, key_id):
        """Unified SSH key deletion across accounts."""
        if self.provider == "hetzner":
            return await self.delete_hetzner_ssh_key(key_id)
        elif self.provider == "vultr":
            return await self.delete_vultr_ssh_key(key_id)
        elif self.provider == "linode":
            return await self.delete_linode_ssh_key(key_id)
        raise ProviderError(f"SSH keys not supported for {self.provider}")

    async def resolve_ssh_keys_for_instance(self, stored_keys):
        """Prepare SSH keys representation suited for create_server given stored keys dicts."""
        if not stored_keys:
            return None
        keys = []
        if self.provider == "hetzner":
            existing = []
            try:
                existing = await self.hetzner_ssh_keys()
            except Exception as exc:
                log.warning("Failed listing existing Hetzner SSH keys: %s", exc)
            existing_by_name = {item.get("name"): item.get("id") for item in existing if item.get("id")}
            existing_by_key = {}
            for item in existing:
                if item.get("id") and item.get("public_key"):
                    parts = str(item["public_key"]).strip().split()
                    if len(parts) >= 2:
                        existing_by_key[f"{parts[0]} {parts[1]}"] = item["id"]

            for k in stored_keys:
                clean_pub = ""
                pub_parts = str(k.get("public_key") or "").strip().split()
                if len(pub_parts) >= 2:
                    clean_pub = f"{pub_parts[0]} {pub_parts[1]}"
                matched_id = existing_by_name.get(k.get("name")) or (existing_by_key.get(clean_pub) if clean_pub else None)
                if matched_id:
                    keys.append(matched_id)
                else:
                    try:
                        hk = await self.create_hetzner_ssh_key(k["name"], k["public_key"])
                        keys.append(hk.get("id") or k["name"])
                    except Exception as exc:
                        if "unique" in str(exc).lower():
                            keys.append(k["name"])
                        else:
                            log.warning("Failed creating Hetzner SSH key %s: %s", k.get("name"), exc)
                            keys.append(k["name"])

        elif self.provider == "vultr":
            existing = []
            try:
                existing = await self.vultr_ssh_keys()
            except Exception as exc:
                log.warning("Failed listing existing Vultr SSH keys: %s", exc)
            existing_map = {item.get("name"): item.get("id") for item in existing if item.get("id")}
            existing_by_key = {}
            for item in existing:
                if item.get("id") and item.get("ssh_key"):
                    parts = str(item["ssh_key"]).strip().split()
                    if len(parts) >= 2:
                        existing_by_key[f"{parts[0]} {parts[1]}"] = item["id"]

            for k in stored_keys:
                clean_pub = ""
                pub_parts = str(k.get("public_key") or "").strip().split()
                if len(pub_parts) >= 2:
                    clean_pub = f"{pub_parts[0]} {pub_parts[1]}"
                matched_id = existing_map.get(k.get("name")) or (existing_by_key.get(clean_pub) if clean_pub else None)
                if matched_id:
                    keys.append(matched_id)
                else:
                    try:
                        vk = await self.create_vultr_ssh_key(k["name"], k["public_key"])
                        if vk.get("id"):
                            keys.append(vk["id"])
                    except Exception as exc:
                        log.warning("Failed creating Vultr SSH key %s: %s", k.get("name"), exc)

        elif self.provider == "linode":
            for k in stored_keys:
                clean_key = str(k.get("public_key") or "").strip()
                if clean_key:
                    keys.append(clean_key)

        elif self.provider == "upcloud":
            # UpCloud has no account-level SSH-key API.  Keep the local vault
            # as the source of truth and pass OpenSSH strings in login_user.
            for k in stored_keys:
                public_key = str(k.get("public_key") or "").strip()
                if public_key:
                    keys.append(public_key)

        elif self.provider == "cloudferro":
            for k in stored_keys:
                public_key = str(k.get("public_key") or "").strip()
                if public_key:
                    keys.append(public_key)

        return keys if keys else None

