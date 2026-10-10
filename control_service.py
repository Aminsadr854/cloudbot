"""Owner automation operations shared by the HTTP API and MCP bridge.

Never return decrypted account credentials, proxy passwords, or server passwords without confirmation.
Cloud resources can cost money, so mutations require an exact confirmation value.
"""

import asyncio
import ipaddress
import logging
import re
import secrets
import time

import aiohttp
from cloudflare import Cloudflare
from providers import Provider, region_country, country_code, country_flag, proxy_url

log = logging.getLogger("cloudbot.control_service")


class InputError(ValueError):
    pass


try:
    from proxy_pool import resolve_country
except Exception:
    def resolve_country(v):
        alias = {"UAE": "AE", "ARE": "AE", "UK": "GB", "USA": "US"}
        cleaned = str(v or "").strip().upper()
        return alias.get(cleaned, cleaned)


def _normalize_country(value):
    raw = str(value or "").strip()
    if not raw:
        return ""
    try:
        return resolve_country(raw)
    except Exception:
        aliases = {"UAE": "AE", "ARE": "AE", "UK": "GB", "USA": "US"}
        clean = raw.upper()
        return aliases.get(clean, clean)


OPERATIONS = {
    "accounts": "List configured cloud accounts without credentials",
    "account_info": "Read a provider account's billing and access details",
    "servers": "List servers in one cloud account",
    "server": "Read one server and its attached floating IPs",
    "regions": "List available server regions",
    "plans": "List available plans for a region",
    "images": "List installable operating-system images",
    "floating_ips": "List floating IPs attached to a server",
    "watch_status": "Read watchdog configuration and recent results",
    "tunnels": "List registered tunnels without their encrypted details",
    "dns_zones": "List Cloudflare zones",
    "dns_record": "Read a Cloudflare A record by fully qualified name",
    "create_server": "Create one server; confirm CREATE_SERVER",
    "power_server": "Start, halt, or reboot a Vultr server; confirm the action in uppercase",
    "create_floating_ip": "Create and attach a Vultr IPv4 or Hetzner IPv4/IPv6; confirm CREATE_FLOATING_IP",
    "delete_floating_ip": "Delete an attached floating IP; confirm DELETE_FLOATING_IP",
    "upsert_dns": "Create or repoint a Cloudflare A record; confirm UPSERT_DNS",
    # Extended operations for Hosting Dashboard:
    "all_servers": "List servers across all accounts with network and spec details",
    "all_floating_ips": "List all floating IPs across accounts with assignment status",
    "assign_floating_ip": "Assign an existing floating IP to a server",
    "unassign_floating_ip": "Unassign/detach a floating IP from its server",
    "update_floating_ip": "Update floating IP reverse DNS PTR or label",
    "delete_server": "Delete a cloud server; confirm DELETE_SERVER",
    "server_password": "Reveal stored root password for a server; confirm SHOW_PASSWORD",
    "ssh_keys": "List saved SSH keys",
    "add_ssh_key": "Add a new SSH public key",
    "delete_ssh_key": "Delete an SSH key; confirm DELETE_SSH_KEY",
    "add_account": "Add a new cloud provider account",
    "delete_account": "Delete a cloud provider account; confirm DELETE_ACCOUNT",
    "check_all_accounts": "Test credentials and read balance/credits across all accounts",
    "apply_promo_code": "Apply a promotional credit code to a Linode account",
    "hetzner_primary_ips": "List Hetzner Primary IPs for an account",
    "create_hetzner_primary_ip": "Create a Hetzner Primary IP; confirm CREATE_PRIMARY_IP",
    "assign_hetzner_primary_ip": "Assign Hetzner Primary IP to server",
    "unassign_hetzner_primary_ip": "Unassign Hetzner Primary IP from server",
    "delete_hetzner_primary_ip": "Delete Hetzner Primary IP; confirm DELETE_PRIMARY_IP",
    "dns_records": "List DNS records in a Cloudflare zone",
    "delete_dns_record": "Delete a Cloudflare DNS record; confirm DELETE_DNS",
    "proxy_pool": "List proxy pool providers, session claims, and active reservations",
    "set_account_proxy": "Set or clear proxy configuration for a cloud provider account",
    "test_account": "Test account connectivity, proxy route, and retrieve live billing",
    "test_proxy": "Test a raw proxy URL or account proxy connection",
    "proxy_providers": "List configured proxy providers with session status",
    "proxy_sessions": "List sessions registered for a proxy provider with allocation and binding status",
    "add_proxy_provider": "Add a new rotating proxy provider to the pool",
    "update_proxy_provider": "Update a proxy provider's label, template, or default status",
    "delete_proxy_provider": "Delete a proxy provider; confirm DELETE_PROXY_PROVIDER",
    "toggle_proxy_provider": "Enable or disable a proxy provider",
    "toggle_proxy_session": "Enable or disable a specific proxy session token in a provider pool",
    "delete_proxy_session": "Delete a specific session token from a proxy provider pool",
    "auto_heal_proxies": "Automatically reassign working proxies from pool to accounts with broken or failed proxies",
    "add_proxy_sessions": "Batch import multiple session IDs into a proxy provider",
    "parse_proxy_sessions": "Parse and extract session IDs from bulk proxy lines",
    "allocate_account_proxy": "Allocate and bind an available proxy from a rotating provider pool for an account",
    "set_account_region": "Set or update an account's geographical region code",
    "proxy_availability": "Check available unallocated sessions for a provider in a specific country",
    "set_server_password": "Save or update stored root password for a server",
    "reset_server_password": "Reset root password on Hetzner and reboot; confirm RESET_PASSWORD",
    "toggle_vultr_backups": "Enable or disable auto-backups for a Vultr server",
    "swap_linode_ips": "Swap IPv4 addresses between two Linodes in the same region; confirm SWAP_LINODE_IPS",
}


def _extract_session_ids_from_text(raw_text, template_username=None):
    if not raw_text:
        return []
    if isinstance(raw_text, list):
        raw_text = "\n".join(str(x) for x in raw_text)
    lines = [line.strip() for line in str(raw_text).splitlines() if line.strip()]
    found = []

    tpl_regex = None
    if template_username and "{session}" in template_username:
        pattern = re.escape(template_username)
        pattern = pattern.replace(re.escape("{country}"), r"(?:[A-Za-z]{2}|[A-Za-z0-9_-]+?)")
        pattern = pattern.replace(re.escape("{session}"), r"(?P<session>[A-Za-z0-9_-]+)")
        try:
            tpl_regex = re.compile(pattern)
        except Exception:
            tpl_regex = None

    for line in lines:
        # Step 1: Skip standalone numbering lines (e.g. "1", "2", "3.", "4)", "#5")
        if re.fullmatch(r'#?\d+[.):]?\s*', line):
            continue

        # Step 2: Strip leading numbering prefix on a proxy line, e.g. "1. host:port:..." or "1 niceproxy.io:..."
        clean_line = re.sub(r'^\s*#?\d+[.):\s]+\s*(?=[a-zA-Z0-9]+://|[a-zA-Z0-9.-]+:\d+)', '', line)

        # Step 3: Extract username candidate
        user_candidate = None
        if "@" in clean_line:
            parts = clean_line.split("@")
            before_at = parts[0].split("://")[-1] if "://" in parts[0] else parts[0]
            if ":" in before_at and not re.search(r'^\d+$', before_at.split(":")[-1]):
                user_candidate = before_at.split(":")[0]
            elif len(parts) > 1 and ":" in parts[1]:
                user_candidate = parts[1].split(":")[0]
        elif ":" in clean_line:
            parts = clean_line.split(":")
            if len(parts) >= 4:
                user_candidate = parts[2]
            elif len(parts) == 3:
                user_candidate = parts[1]

        target_text = user_candidate if user_candidate else clean_line

        # Step 4: If provider template regex is available, test against candidate and line
        if tpl_regex:
            m = tpl_regex.search(target_text) or tpl_regex.search(clean_line)
            if m:
                found.append(m.group("session"))
                continue

        # Step 5: Heuristic search for sid/ssid/session patterns
        m = re.search(r'(?:ssid|sid|session)[_-]([a-zA-Z0-9_-]+?)(?:_(?:time|life|sst)|-(?:sst|time)|[:@/\s]|$)', target_text, re.IGNORECASE)
        if not m:
            m = re.search(r'(?:ssid|sid|session)[_-]([a-zA-Z0-9_-]+)', target_text, re.IGNORECASE)
        if m:
            found.append(m.group(1))
            continue

        # Step 6: User candidate with country tag
        if user_candidate and user_candidate != clean_line:
            m = re.search(r'country[_-][A-Za-z]{2}[_-]([a-zA-Z0-9_-]+)', user_candidate, re.IGNORECASE)
            if m:
                found.append(m.group(1))
                continue
            found.append(user_candidate)
            continue

        # Step 7: Single clean token
        token = re.sub(r'[^a-zA-Z0-9_\-]', '', clean_line)
        if token:
            found.append(token)

    seen = set()
    return [x for x in found if not (x in seen or seen.add(x))]


def _required(args, name):
    value = args.get(name)
    if value is None or isinstance(value, bool) or not str(value).strip():
        raise InputError(f"{name} is required")
    return str(value).strip()


def _confirm(args, expected):
    if args.get("confirm") != expected:
        raise InputError(f"confirm must be exactly {expected}")


def _account(store, args):
    try:
        account_id = int(_required(args, "account_id"))
    except ValueError as exc:
        raise InputError("account_id must be an integer") from exc
    account = store.account(account_id)
    if not account:
        raise InputError("account not found")
    return account


def _account_public(account, store=None):
    proxy_val = account.get("proxy")
    masked = None
    binding_info = None
    if store and account.get("id"):
        try:
            b = store.proxy_binding(account["id"])
            if b:
                binding_info = b
        except Exception:
            pass
    region = account.get("region") or ""
    if not region and binding_info and binding_info.get("country"):
        region = binding_info["country"]
    if proxy_val:
        try:
            if "@" in proxy_val:
                parts = proxy_val.split("@")
                masked = f"***@{parts[1]}"
            else:
                masked = "configured"
        except Exception:
            masked = "configured"
    return {
        "id": account.get("id"),
        "label": account.get("label"),
        "provider": account.get("provider"),
        "proxy_family": account.get("proxy_family") or "default",
        "auto_backup": account.get("auto_backup") or "disabled",
        "region": region,
        "binding": binding_info,
        "created_at": account.get("created_at"),
        "has_proxy": bool(proxy_val),
        "proxy_masked": masked,
    }


def _server_public(server):
    return {key: value for key, value in server.items()
            if key not in {"root_password", "default_password", "password", "token"}}


def _floating_value(row):
    return row.get("ip") or row.get("ip_address") or row.get("subnet") or row.get("network")


async def _floating(provider, server_id):
    if provider.provider == "vultr":
        return await provider.vultr_floating_ips(server_id)
    if provider.provider == "hetzner":
        return await provider.hetzner_floating_ips(server_id)
    return []


_OP_CACHE = {}


def _get_op_cache(k):
    now = time.time()
    if k in _OP_CACHE:
        exp, val = _OP_CACHE[k]
        if now < exp:
            return val
        del _OP_CACHE[k]
    return None


def _set_op_cache(k, val, ttl=3600):
    _OP_CACHE[k] = (time.time() + ttl, val)


def _get_cache(store, k, default=None):
    if hasattr(store, "get_cache"):
        return store.get_cache(k, default)
    return default


def _set_cache(store, k, val):
    if hasattr(store, "set_cache"):
        store.set_cache(k, val)


def _delete_cache(store, k):
    if hasattr(store, "delete_cache"):
        store.delete_cache(k)


async def execute(operation, args, store):
    """Execute one documented operation with validated, JSON-safe arguments."""
    if operation not in OPERATIONS:
        raise InputError("unknown operation")
    if not isinstance(args, dict):
        raise InputError("args must be a JSON object")

    # ---- Accounts Overview ---------------------------------------------
    if operation == "accounts":
        return {"accounts": [_account_public(a, store) for a in store.accounts()]}

    if operation == "add_account":
        label = _required(args, "label")
        provider_name = _required(args, "provider").lower()
        if provider_name not in ("linode", "vultr", "hetzner"):
            raise InputError("provider must be linode, vultr, or hetzner")
        token = _required(args, "token")
        proxy = args.get("proxy") or None
        proxy_family = args.get("proxy_family") or "default"
        auto_backup = args.get("auto_backup") or "disabled"
        region = _normalize_country(args.get("region"))
        proxy_provider_id = args.get("proxy_provider_id")
        if proxy_provider_id and not region:
            raise InputError("Account country / region is required to allocate from proxy providers")

        if hasattr(store, "add_account") and "region" in store.add_account.__code__.co_varnames:
            acc_id = store.add_account(label, provider_name, token, proxy=proxy,
                                       proxy_family=proxy_family, auto_backup=auto_backup, region=region)
        else:
            acc_id = store.add_account(label, provider_name, token, proxy=proxy,
                                       proxy_family=proxy_family, auto_backup=auto_backup)

        allocated_info = None
        if proxy_provider_id:
            try:
                if str(proxy_provider_id).lower() == "auto":
                    enabled_providers = [p for p in store.proxy_providers() if p.get("enabled")]
                    if not enabled_providers:
                        raise InputError("No active rotating proxy providers found in system")
                    alloc_res = None
                    last_exc = None
                    for p in enabled_providers:
                        try:
                            alloc_res = store.allocate_proxy(p["id"], region, acc_id)
                            break
                        except Exception as exc:
                            last_exc = exc
                    if not alloc_res:
                        raise InputError(f"No available proxy sessions for region {region}: {last_exc}")
                else:
                    pid = int(proxy_provider_id)
                    alloc_res = store.allocate_proxy(pid, region, acc_id)

                store.set_proxy(acc_id, alloc_res["proxy"], alloc_res.get("family", "default"), proxy_request=alloc_res.get("token"))
                allocated_info = alloc_res
            except Exception as e:
                store.delete_account(acc_id)
                raise InputError(f"Failed to allocate proxy from provider: {e}")

        _delete_cache(store, "all_servers")
        _delete_cache(store, "all_floating_ips")
        _delete_cache(store, "all_billing")
        resp = {"id": acc_id, "label": label, "provider": provider_name, "region": region}
        if allocated_info:
            resp["allocated_proxy"] = {
                "country": allocated_info.get("country", region),
                "session": allocated_info.get("session"),
                "proxy": allocated_info.get("proxy"),
            }
        return resp

    if operation == "delete_account":
        _confirm(args, "DELETE_ACCOUNT")
        account_id = int(_required(args, "account_id"))
        n = store.delete_account(account_id)
        _delete_cache(store, "all_servers")
        _delete_cache(store, "all_floating_ips")
        _delete_cache(store, "all_billing")
        _delete_cache(store, f"primary_ips:{account_id}")
        return {"deleted": n > 0, "account_id": account_id}

    if operation == "check_all_accounts":
        force_refresh = bool(args.get("refresh") or args.get("force"))
        if not force_refresh:
            cached = _get_cache(store, "all_billing")
            if cached is not None and isinstance(cached, dict) and "accounts" in cached:
                return cached

        accs = store.accounts()

        async def _check_one(acc):
            try:
                p = Provider(acc)
                info = await p.account_info()
                ident = await p.whoami()
                return {
                    "account": _account_public(acc, store),
                    "status": "ok",
                    "info": info,
                    "identity": ident,
                }
            except Exception as exc:
                return {
                    "account": _account_public(acc, store),
                    "status": "error",
                    "error": str(exc),
                }

        results = await asyncio.gather(*[_check_one(a) for a in accs], return_exceptions=True)
        res = {"accounts": [r for r in results if isinstance(r, dict)], "cached_at": time.time()}
        _set_cache(store, "all_billing", res)
        return res

    if operation == "test_account":
        account = _account(store, args)
        p = Provider(account)
        start_t = time.time()
        try:
            ident = await p.whoami()
            info = await p.account_info()
            latency_ms = round((time.time() - start_t) * 1000, 1)
            return {
                "status": "ok",
                "account": _account_public(account, store),
                "identity": ident,
                "info": info,
                "latency_ms": latency_ms,
            }
        except Exception as exc:
            return {
                "status": "error",
                "account": _account_public(account, store),
                "error": str(exc),
            }

    if operation == "set_account_region":
        account = _account(store, args)
        region = _normalize_country(args.get("region"))
        if hasattr(store, "set_account_region"):
            store.set_account_region(account["id"], region)
        _delete_cache(store, "all_billing")
        updated = store.account(account["id"])
        return {"updated": True, "account": _account_public(updated, store)}

    if operation == "allocate_account_proxy":
        account = _account(store, args)
        provider_id = int(_required(args, "provider_id"))
        country = _normalize_country(args.get("country") or account.get("region"))
        if not country:
            raise InputError("Country / Region is required to allocate from proxy pool")
        another = bool(args.get("another", False))
        res = store.allocate_proxy(provider_id, country, account["id"], another=another)
        store.set_proxy(account["id"], res["proxy"], res.get("family", "default"), proxy_request=res.get("token"))
        if hasattr(store, "set_account_region"):
            store.set_account_region(account["id"], res.get("country", country))
        _delete_cache(store, "all_billing")
        updated = store.account(account["id"])
        return {"updated": True, "account": _account_public(updated, store), "allocated": res}

    if operation == "proxy_availability":
        provider_id_arg = args.get("provider_id")
        country = _normalize_country(_required(args, "country"))
        if not country:
            raise InputError("country is required")
        if not provider_id_arg or str(provider_id_arg).lower() == "auto":
            total_avail = 0
            providers_info = []
            for p in store.proxy_providers():
                if p.get("enabled"):
                    try:
                        cnt = store.proxy_availability(p["id"], country)
                        total_avail += cnt
                        providers_info.append({"id": p["id"], "label": p["label"], "available": cnt})
                    except Exception:
                        pass
            return {"provider_id": "auto", "country": country, "available": total_avail, "providers": providers_info}
        else:
            provider_id = int(provider_id_arg)
            count = store.proxy_availability(provider_id, country)
            return {"provider_id": provider_id, "country": country, "available": count}

    if operation == "set_account_proxy":
        account = _account(store, args)
        proxy = args.get("proxy")
        proxy_family = args.get("proxy_family") or "default"
        if proxy is not None:
            proxy = str(proxy).strip()
            if not proxy:
                proxy = None
        store.set_proxy(account["id"], proxy, proxy_family=proxy_family)
        if "region" in args and hasattr(store, "set_account_region"):
            store.set_account_region(account["id"], _normalize_country(args["region"]))
        _delete_cache(store, "all_billing")
        updated = store.account(account["id"])
        return {"updated": True, "account": _account_public(updated, store)}

    if operation == "apply_promo_code":
        account = _account(store, args)
        if account["provider"] != "linode":
            raise InputError("Promo codes are only supported for Linode accounts")
        promo_code = _required(args, "promo_code").strip()
        provider = Provider(account)
        res = await provider.apply_linode_promo_code(promo_code)
        _delete_cache(store, "all_billing")
        return {"applied": True, "account_id": account["id"], "promo_code": promo_code, "promotion": res}

    if operation == "test_proxy":
        raw_proxy = args.get("proxy")
        if not raw_proxy and args.get("account_id"):
            acc = _account(store, args)
            raw_proxy = acc.get("proxy")
        if not raw_proxy:
            raise InputError("proxy string or account_id with configured proxy is required")

        p_url = proxy_url(raw_proxy)
        start_t = time.time()
        try:
            headers = {"User-Agent": "Mozilla/5.0"}
            is_socks = bool(p_url) and p_url.startswith(("socks5", "socks4"))
            timeout = aiohttp.ClientTimeout(total=10)
            if is_socks:
                try:
                    from aiohttp_socks import ProxyConnector
                    conn = ProxyConnector.from_url(p_url)
                    async with aiohttp.ClientSession(timeout=timeout, connector=conn) as s:
                        async with s.get("https://api.ipify.org?format=json", headers=headers) as r:
                            data = await r.json()
                except ImportError:
                    raise InputError("aiohttp-socks is required for SOCKS proxy testing")
            else:
                async with aiohttp.ClientSession(timeout=timeout) as s:
                    async with s.get("https://api.ipify.org?format=json", proxy=p_url, headers=headers) as r:
                        data = await r.json()
            latency_ms = round((time.time() - start_t) * 1000, 1)
            return {"status": "ok", "ip": data.get("ip"), "latency_ms": latency_ms}
        except Exception as exc:
            return {"status": "error", "error": str(exc)}

    if operation == "proxy_providers":
        providers_list = store.proxy_providers()
        bindings = {}
        for acc in store.accounts():
            b = store.proxy_binding(acc["id"])
            if b:
                bindings.setdefault(b["provider_id"], []).append({
                    "account_id": acc["id"],
                    "account_label": acc["label"],
                    "country": b["country"],
                    "session_id": b["session_id"],
                })
        for p in providers_list:
            sessions = store.proxy_sessions(p["id"])
            p["total_sessions"] = len(sessions)
            p["active_sessions"] = sum(1 for s in sessions if s.get("enabled", 1))
            p["bound_accounts"] = bindings.get(p["id"], [])
            tpl = p.get("template") or {}
            scheme = tpl.get("scheme", "http")
            host = tpl.get("host", "")
            port = tpl.get("port", "")
            username = tpl.get("username", "")
            p["template_public"] = {
                "host": host,
                "port": port,
                "scheme": scheme,
                "username": username,
                "display": f"{scheme}://{username}:••••••@{host}:{port}" if username else f"{scheme}://{host}:{port}",
            }
        return {"providers": providers_list}

    if operation == "proxy_sessions":
        pid = int(_required(args, "provider_id"))
        p = store.proxy_provider(pid)
        if not p:
            raise InputError("Proxy provider not found")
        sessions = store.proxy_sessions(pid)
        bindings_by_session = {}
        for acc in store.accounts():
            b = store.proxy_binding(acc["id"])
            if b and b.get("provider_id") == pid:
                sid = b.get("session_id")
                if sid:
                    bindings_by_session[sid] = {
                        "account_id": acc["id"],
                        "account_label": acc["label"],
                        "country": b.get("country"),
                    }
        enriched = []
        for s in sessions:
            s_copy = dict(s)
            sid = s_copy.get("session_id")
            s_copy["bound_to"] = bindings_by_session.get(sid)
            s_copy["is_bound"] = sid in bindings_by_session
            enriched.append(s_copy)
        return {
            "provider_id": pid,
            "provider_label": p.get("label"),
            "sessions": enriched,
            "total_count": len(enriched),
            "active_count": sum(1 for s in enriched if s.get("enabled", 1)),
            "bound_count": sum(1 for s in enriched if s.get("is_bound")),
        }

    if operation == "add_proxy_provider":
        label = _required(args, "label")
        template = _required(args, "template")
        ids_input = args.get("session_ids") or ""
        from proxy_pool import session_ids, import_format, proxy_string, ProxyPoolError

        if isinstance(template, dict):
            tpl_dict = template
        elif isinstance(template, str):
            tpl_str = template.strip()
            scheme = args.get("scheme", "http").lower()
            if "://" not in tpl_str and not tpl_str.startswith(("http://", "https://", "socks4://", "socks5://")):
                tpl_str = f"{scheme}://{tpl_str}"
            tpl_dict, extra_ids = import_format(tpl_str)
            if extra_ids and not ids_input:
                ids_input = extra_ids
        else:
            raise InputError("Invalid template format")

        if isinstance(ids_input, list):
            raw_ids = [str(x).strip() for x in ids_input]
        elif isinstance(ids_input, str):
            range_match = re.fullmatch(r'(\d+)\s*-\s*(\d+)', ids_input.strip())
            if range_match:
                start_n, end_n = int(range_match.group(1)), int(range_match.group(2))
                if 0 <= start_n <= end_n and (end_n - start_n) <= 2000:
                    raw_ids = [str(i) for i in range(start_n, end_n + 1)]
                else:
                    raw_ids = []
            else:
                raw_ids = _extract_session_ids_from_text(ids_input, template_username=tpl_dict.get("username"))
                if not raw_ids:
                    raw_ids = [l.strip() for l in ids_input.replace(",", "\n").splitlines() if l.strip()]
        else:
            raw_ids = []

        ids = session_ids("\n".join(raw_ids))
        if not ids:
            raise InputError("At least one valid session ID is required")

        pid = store.add_proxy_provider(label, tpl_dict, ids, family=args.get("family", "default"))
        return {"id": pid, "label": label, "sessions_count": len(ids)}

    if operation == "update_proxy_provider":
        pid = int(_required(args, "provider_id"))
        updated = {}
        if "label" in args and str(args["label"]).strip():
            new_label = str(args["label"]).strip()
            store.manage_proxy_provider(pid, "rename", new_label)
            updated["label"] = new_label
        if "template" in args and args["template"]:
            from proxy_pool import import_format
            tpl = args["template"]
            if isinstance(tpl, str):
                scheme = args.get("scheme", "http").lower()
                if "://" not in tpl and not tpl.startswith(("http://", "https://", "socks4://", "socks5://")):
                    tpl = f"{scheme}://{tpl}"
                tpl, _ = import_format(tpl)
            store.manage_proxy_provider(pid, "format", tpl)
            updated["template"] = tpl
        if "default" in args and args["default"]:
            store.manage_proxy_provider(pid, "default")
            updated["default"] = True
        return {"updated": True, "provider_id": pid, **updated}

    if operation == "delete_proxy_provider":
        _confirm(args, "DELETE_PROXY_PROVIDER")
        pid = int(_required(args, "provider_id"))
        store.manage_proxy_provider(pid, "delete")
        return {"deleted": True, "provider_id": pid}

    if operation == "toggle_proxy_provider":
        pid = int(_required(args, "provider_id"))
        store.manage_proxy_provider(pid, "toggle")
        return {"toggled": True, "provider_id": pid}

    if operation == "toggle_proxy_session":
        pid = int(_required(args, "provider_id"))
        sid = str(_required(args, "session_id")).strip()
        store.manage_proxy_session(pid, sid, "toggle")
        return {"toggled": True, "provider_id": pid, "session_id": sid}

    if operation == "delete_proxy_session":
        pid = int(_required(args, "provider_id"))
        sid = str(_required(args, "session_id")).strip()
        store.manage_proxy_session(pid, sid, "delete")
        return {"deleted": True, "provider_id": pid, "session_id": sid}

    if operation == "add_proxy_sessions":
        pid = int(_required(args, "provider_id"))
        p = store.proxy_provider(pid) if hasattr(store, "proxy_provider") else None
        tpl = (p.get("template") if p else {}) or {}
        tpl_username = tpl.get("username") if isinstance(tpl, dict) else None
        raw = args.get("raw_text") or args.get("session_ids") or args.get("session_id") or ""
        extracted = []
        if isinstance(raw, str) and re.fullmatch(r'(\d+)\s*-\s*(\d+)', raw.strip()):
            m = re.fullmatch(r'(\d+)\s*-\s*(\d+)', raw.strip())
            s_n, e_n = int(m.group(1)), int(m.group(2))
            if 0 <= s_n <= e_n and (e_n - s_n) <= 2000:
                extracted = [str(i) for i in range(s_n, e_n + 1)]
        if not extracted:
            extracted = _extract_session_ids_from_text(raw, template_username=tpl_username)
        if not extracted and isinstance(raw, str):
            lines = [l.strip() for l in raw.replace(",", "\n").splitlines() if l.strip()]
            if lines and all(re.fullmatch(r'[A-Za-z0-9_-]{1,128}', l) for l in lines):
                extracted = list(dict.fromkeys(lines))
        if not extracted:
            raise InputError("No valid session IDs found in input")
        if hasattr(store, "add_proxy_sessions"):
            added = store.add_proxy_sessions(pid, extracted)
        else:
            added = len(extracted)
        total_sessions = len(store.proxy_sessions(pid)) if hasattr(store, "proxy_sessions") else added
        return {"provider_id": pid, "added": added, "extracted": extracted, "count": len(extracted), "total_sessions": total_sessions}

    if operation == "parse_proxy_sessions":
        pid = args.get("provider_id")
        tpl_username = None
        if pid and hasattr(store, "proxy_provider"):
            try:
                p = store.proxy_provider(int(pid))
                if p and isinstance(p.get("template"), dict):
                    tpl_username = p["template"].get("username")
            except Exception:
                pass
        raw = args.get("raw_text") or args.get("text") or ""
        extracted = _extract_session_ids_from_text(raw, template_username=tpl_username)
        return {"session_ids": extracted, "count": len(extracted)}

    if operation == "auto_heal_proxies":
        accs = store.accounts()
        target_account_id = args.get("account_id")
        if target_account_id is not None:
            accs = [a for a in accs if a["id"] == int(target_account_id)]

        providers_list = store.proxy_providers() if hasattr(store, "proxy_providers") else []
        enabled_pids = [p["id"] for p in providers_list if p.get("enabled", 1)]
        if not enabled_pids:
            raise InputError("No active proxy pool providers available to allocate from")

        healed = []
        failed = []
        skipped = []

        for acc in accs:
            # Check if proxy is broken
            is_broken = False
            error_reason = ""
            try:
                p = Provider(acc)
                await asyncio.wait_for(p.whoami(), timeout=10)
            except Exception as e:
                is_broken = True
                error_reason = str(e)

            if not is_broken and not args.get("force", False):
                skipped.append({"id": acc["id"], "label": acc["label"], "reason": "Connection healthy"})
                continue

            # Need to heal: target country
            country = (acc.get("region") or "").strip().upper()
            if not country and hasattr(store, "proxy_binding"):
                b = store.proxy_binding(acc["id"])
                if b and b.get("country"):
                    country = b["country"]
            if not country:
                country = "DE"  # default fallback

            allocated = False
            for pid in enabled_pids:
                try:
                    res = store.allocate_proxy(pid, country, acc["id"], another=True)
                    store.set_proxy(acc["id"], res["proxy"], res.get("family", "default"), proxy_request=res.get("token"))
                    if hasattr(store, "set_account_region") and not acc.get("region"):
                        store.set_account_region(acc["id"], country)

                    # Verify newly assigned proxy
                    updated_acc = store.account(acc["id"])
                    p_new = Provider(updated_acc)
                    start_t = time.time()
                    ident = await asyncio.wait_for(p_new.whoami(), timeout=12)
                    lat_ms = round((time.time() - start_t) * 1000, 1)

                    healed.append({
                        "id": acc["id"],
                        "label": acc["label"],
                        "country": country,
                        "provider_id": pid,
                        "session_id": res.get("session_id"),
                        "identity": ident,
                        "latency_ms": lat_ms,
                        "previous_error": error_reason,
                    })
                    allocated = True
                    break
                except Exception as alloc_err:
                    log.warning("Auto-heal failed for account %s on provider %s: %s", acc["id"], pid, alloc_err)
                    continue

            if not allocated:
                failed.append({
                    "id": acc["id"],
                    "label": acc["label"],
                    "country": country,
                    "error": f"Failed allocating working proxy: {error_reason or 'No capacity'}",
                })

        if healed:
            # Proxy changes invalidate cached account checks and the account
            # error fields embedded in server and Floating IP snapshots.
            _delete_cache(store, "all_billing")
            _delete_cache(store, "all_servers")
            _delete_cache(store, "all_floating_ips")

        return {
            "healed": healed,
            "failed": failed,
            "skipped": skipped,
            "healed_count": len(healed),
            "failed_count": len(failed),
        }

    # ---- SSH Keys ------------------------------------------------------
    if operation == "ssh_keys":
        return {"ssh_keys": store.ssh_keys()}

    if operation == "add_ssh_key":
        name = _required(args, "name")
        public_key = _required(args, "public_key")
        key_id = store.add_ssh_key(name, public_key)
        sync_results = {}
        if args.get("sync_accounts"):
            for acc in store.accounts():
                try:
                    p = Provider(acc)
                    await p.create_ssh_key(name, public_key)
                    sync_results[acc["id"]] = "synced"
                except Exception as exc:
                    sync_results[acc["id"]] = f"error: {exc}"
        key_data = store.ssh_key(key_id)
        return {"ssh_key": key_data, "sync": sync_results}

    if operation == "delete_ssh_key":
        _confirm(args, "DELETE_SSH_KEY")
        key_id = int(_required(args, "key_id"))
        deleted = store.delete_ssh_key(key_id)
        return {"deleted": deleted, "key_id": key_id}

    # ---- All Servers & Floating IPs (Multi-cloud Dashboard) ------------
    if operation == "all_servers":
        force_refresh = bool(args.get("refresh") or args.get("force"))
        if not force_refresh:
            cached = _get_cache(store, "all_servers")
            if cached is not None and isinstance(cached, dict) and "servers" in cached:
                cached_at = cached.get("cached_at")
                if cached_at is None or (time.time() - cached_at < 300):
                    return cached

        accs = store.accounts()
        account_errors = {}

        async def _fetch_acc_servers(acc):
            try:
                p = Provider(acc)
                s_list = await p.list_servers()
                f_map = {}
                if acc["provider"] == "hetzner":
                    try:
                        for f in await p.hetzner_floating_ips():
                            s_id = str(f.get("server") or "")
                            if s_id:
                                f_map.setdefault(s_id, []).append({
                                    "id": str(f.get("id")),
                                    "ip": f.get("ip") or (f.get("network") if isinstance(f.get("network"), str) else ""),
                                    "type": f.get("type"),
                                    "name": f.get("name"),
                                    })
                    except Exception:
                        pass
                elif acc["provider"] == "vultr":
                    try:
                        for f in await p.vultr_reserved_ips():
                            s_id = str(f.get("instance_id") or "")
                            if s_id:
                                f_map.setdefault(s_id, []).append({
                                    "id": str(f.get("id")),
                                    "ip": f.get("subnet") or f.get("ip_address"),
                                    "type": "ipv4" if f.get("ip_type") in ("v4", "ipv4") else "ipv6",
                                    "name": f.get("label"),
                                    })
                    except Exception:
                        pass

                enriched = []
                for s in s_list:
                    sp = _server_public(s)
                    s_id = str(sp.get("id") or "")
                    sp["account_id"] = acc["id"]
                    sp["account_label"] = acc["label"]
                    sp["provider"] = acc["provider"]
                    sp["floating_ips"] = f_map.get(s_id, [])
                    enriched.append(sp)
                return enriched
            except Exception as exc:
                log.warning("Failed listing servers for account %s: %s", acc["id"], exc)
                account_errors[str(acc["id"])] = str(exc)
                return []

        gathered = await asyncio.gather(*[_fetch_acc_servers(a) for a in accs], return_exceptions=True)
        servers = []
        for g in gathered:
            if isinstance(g, list):
                servers.extend(g)
        result = {"servers": servers, "account_errors": account_errors, "cached_at": time.time()}
        _set_cache(store, "all_servers", result)
        return result

    if operation == "all_floating_ips":
        acc_id = args.get("account_id")
        force_refresh = bool(args.get("refresh") or args.get("force"))
        if acc_id is None and not force_refresh:
            cached = _get_cache(store, "all_floating_ips")
            if cached is not None and isinstance(cached, dict) and "floating_ips" in cached:
                cached_at = cached.get("cached_at")
                if cached_at is None or (time.time() - cached_at < 300):
                    return cached

        if acc_id is not None:
            accs = [store.account(int(acc_id))]
            accs = [a for a in accs if a]
        else:
            accs = store.accounts()

        async def _fetch_acc_fips(acc):
            rows = []
            try:
                p = Provider(acc)
                if acc["provider"] == "hetzner":
                    fips = await p.hetzner_floating_ips()
                    for f in fips:
                        srv_id = str(f.get("server") or "") or None
                        loc = (f.get("home_location") or {}).get("name") if isinstance(f.get("home_location"), dict) else f.get("home_location")
                        rows.append({
                            "id": str(f.get("id")),
                            "account_id": acc["id"],
                            "account_label": acc["label"],
                            "provider": "hetzner",
                            "ip": f.get("ip") or f.get("network"),
                            "type": f.get("type", "ipv4"),
                            "name": f.get("name") or "",
                            "server_id": srv_id,
                            "region": loc,
                            "country": region_country("hetzner", loc),
                            "dns_ptr": f.get("dns_ptr"),
                            "status": "assigned" if srv_id else "unassigned",
                            "protection": bool((f.get("protection") or {}).get("delete")),
                        })
                elif acc["provider"] == "vultr":
                    rips = await p.vultr_reserved_ips()
                    for r in rips:
                        inst_id = str(r.get("instance_id") or "") or None
                        rows.append({
                            "id": str(r.get("id")),
                            "account_id": acc["id"],
                            "account_label": acc["label"],
                            "provider": "vultr",
                            "ip": r.get("subnet") or r.get("ip_address"),
                            "type": "ipv4" if r.get("ip_type") in ("v4", "ipv4") else "ipv6",
                            "name": r.get("label") or "",
                            "server_id": inst_id,
                            "region": r.get("region"),
                            "country": region_country("vultr", r.get("region")),
                            "dns_ptr": r.get("reverse"),
                            "status": "assigned" if inst_id else "unassigned",
                            "protection": False,
                        })
            except Exception as exc:
                log.warning("Failed listing floating IPs for account %s: %s", acc["id"], exc)
            return rows

        gathered = await asyncio.gather(*[_fetch_acc_fips(a) for a in accs], return_exceptions=True)
        all_fips = []
        for g in gathered:
            if isinstance(g, list):
                all_fips.extend(g)
        result = {"floating_ips": all_fips, "cached_at": time.time()}
        if acc_id is None:
            _set_cache(store, "all_floating_ips", result)
        return result

    # ---- Watchdog & Tunnels & Proxy Pool --------------------------------
    if operation == "watch_status":
        cfg = store.watch_cfg()
        return {"enabled": cfg.get("enabled"), "auto_replace": cfg.get("auto_replace"),
                "interval_minutes": cfg.get("interval_minutes"),
                "targets": [{key: row.get(key) for key in ("id", "label", "host", "port")}
                            for row in store.watch_targets()],
                "last_results": store.watch_last()}

    if operation == "tunnels":
        return {"tunnels": [{key: row.get(key) for key in
                             ("id", "kind", "iran_host", "foreign_host", "ports", "created_at")}
                            for row in store.tunnels()]}

    if operation == "proxy_pool":
        providers_list = store.proxy_providers()
        claims = [dict(c) for c in store.con.execute("SELECT * FROM proxy_claims ORDER BY claimed_at DESC LIMIT 50")]
        return {"providers": providers_list, "recent_claims": claims}

    # ---- Cloudflare DNS ------------------------------------------------
    if operation in {"dns_zones", "dns_record", "dns_records", "upsert_dns", "delete_dns_record"}:
        token = store.cf_token()
        if not token:
            if operation == "dns_zones":
                return {"zones": [], "configured": False}
            raise InputError("Cloudflare token is not configured")
        cf = Cloudflare(token)

        if operation == "dns_zones":
            return {"zones": [{"id": zid, "name": name} for zid, name in await cf.zones()]}

        if operation == "dns_records":
            zone_id = args.get("zone_id")
            if not zone_id and args.get("zone_name"):
                z = await cf.zone_for(args["zone_name"])
                if z:
                    zone_id = z[0]
            if not zone_id:
                raise InputError("zone_id or zone_name is required")
            records = await cf._req("GET", f"/zones/{zone_id}/dns_records?per_page=100")
            return {"records": [_dns_public(r) for r in records]}

        if operation == "delete_dns_record":
            _confirm(args, "DELETE_DNS")
            zone_id = _required(args, "zone_id")
            record_id = _required(args, "record_id")
            await cf.delete_record(zone_id, record_id)
            return {"deleted": True, "record_id": record_id}

        name = _required(args, "name").rstrip(".").lower()
        if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,251}[a-z0-9]", name):
            raise InputError("name must be a fully qualified DNS name")
        zone = await cf.zone_for(name)
        if not zone:
            raise InputError("no accessible Cloudflare zone matches name")
        zone_id, zone_name = zone
        record = await cf.find_a_record(zone_id, name)
        if operation == "dns_record":
            return {"zone": zone_name, "record": _dns_public(record)}
        _confirm(args, "UPSERT_DNS")
        ip = _required(args, "ip")
        try:
            if ipaddress.ip_address(ip).version != 4:
                raise InputError("A records require IPv4")
        except ValueError as exc:
            raise InputError("ip must be a valid IPv4 address") from exc
        if record:
            result = await cf.update_a(zone_id, record, ip)
            action = "updated"
        else:
            result = await cf.create_a(zone_id, name, ip, proxied=False)
            action = "created"
        return {"action": action, "zone": zone_name, "record": _dns_public(result)}

    # ---- Per-Account Provider Operations -------------------------------
    account = _account(store, args)
    provider = Provider(account)
    account_id = account["id"]

    if operation == "account_info":
        return {"account": _account_public(account), "info": await provider.account_info(),
                "identity": await provider.whoami()}

    if operation == "servers":
        return {"account": _account_public(account),
                "servers": [_server_public(s) for s in await provider.list_servers()]}

    if operation == "regions":
        force = bool(args.get("force") or args.get("refresh"))
        cache_key = f"regions:{account['provider']}:{account['id']}"
        if not force:
            cached = _get_op_cache(cache_key)
            if cached is not None:
                return cached
            stored = _get_cache(store, cache_key)
            if stored is not None and isinstance(stored, dict) and "regions" in stored:
                _set_op_cache(cache_key, stored, ttl=86400)
                return stored
        res = await provider.regions(force=force)
        if provider.provider == "linode":
            asyncio.create_task(provider.precache_linode_plans(res))
        out = {"regions": [{"id": key, "label": label} for key, label in res]}
        _set_op_cache(cache_key, out, ttl=86400)
        _set_cache(store, cache_key, out)
        return out

    if operation == "plans":
        region = _required(args, "region")
        force = bool(args.get("force") or args.get("refresh"))
        cache_key = f"plans:{account['provider']}:{account['id']}:{region}"
        if not force:
            cached = _get_op_cache(cache_key)
            if cached is not None:
                return cached
            stored = _get_cache(store, cache_key)
            if stored is not None and isinstance(stored, dict) and "plans" in stored:
                _set_op_cache(cache_key, stored, ttl=86400)
                return stored
        res = await provider.plans(region, force=force)
        out = {"region": region, "plans": [{"id": key, "label": label} for key, label in res]}
        _set_op_cache(cache_key, out, ttl=86400)
        _set_cache(store, cache_key, out)
        return out

    if operation == "images":
        force = bool(args.get("force") or args.get("refresh"))
        cache_key = f"images:{account['provider']}:{account['id']}"
        if not force:
            cached = _get_op_cache(cache_key)
            if cached is not None:
                return cached
            stored = _get_cache(store, cache_key)
            if stored is not None and isinstance(stored, dict) and "images" in stored:
                _set_op_cache(cache_key, stored, ttl=86400)
                return stored
        try:
            res = await provider.images(force=force)
        except TypeError:
            res = await provider.images()
        out = {"images": [{"id": key, "label": label} for key, label in res]}
        _set_op_cache(cache_key, out, ttl=86400)
        _set_cache(store, cache_key, out)
        return out

    if operation == "hetzner_primary_ips":
        if account["provider"] != "hetzner":
            raise InputError("Primary IPs are only supported on Hetzner")
        cache_key = f"primary_ips:{account['id']}"
        force_refresh = bool(args.get("refresh") or args.get("force"))
        if not force_refresh:
            cached = _get_cache(store, cache_key)
            if cached is not None and isinstance(cached, dict) and "primary_ips" in cached:
                return cached
        pips = await provider.hetzner_primary_ips()
        res = {"primary_ips": pips, "cached_at": time.time()}
        _set_cache(store, cache_key, res)
        return res

    if operation == "create_hetzner_primary_ip":
        _confirm(args, "CREATE_PRIMARY_IP")
        if account["provider"] != "hetzner":
            raise InputError("Primary IPs are only supported on Hetzner")
        location = _required(args, "location")
        ip_type = _required(args, "ip_type")
        name = _required(args, "name")
        res = await provider.create_hetzner_primary_ip(location, ip_type, name)
        _delete_cache(store, f"primary_ips:{account_id}")
        return {"primary_ip": res}

    if operation == "assign_hetzner_primary_ip":
        if account["provider"] != "hetzner":
            raise InputError("Primary IPs are only supported on Hetzner")
        ip_id = _required(args, "ip_id")
        server_id = _required(args, "server_id")
        res = await provider.assign_hetzner_primary_ip(ip_id, server_id)
        _delete_cache(store, f"primary_ips:{account_id}")
        _delete_cache(store, "all_servers")
        return {"result": res}

    if operation == "unassign_hetzner_primary_ip":
        if account["provider"] != "hetzner":
            raise InputError("Primary IPs are only supported on Hetzner")
        ip_id = _required(args, "ip_id")
        res = await provider.unassign_hetzner_primary_ip(ip_id)
        _delete_cache(store, f"primary_ips:{account_id}")
        _delete_cache(store, "all_servers")
        return {"result": res}

    if operation == "delete_hetzner_primary_ip":
        _confirm(args, "DELETE_PRIMARY_IP")
        if account["provider"] != "hetzner":
            raise InputError("Primary IPs are only supported on Hetzner")
        ip_id = _required(args, "ip_id")
        await provider.delete_hetzner_primary_ip(ip_id)
        _delete_cache(store, f"primary_ips:{account_id}")
        return {"deleted": True, "ip_id": ip_id}

    if operation == "create_server":
        _confirm(args, "CREATE_SERVER")
        name = _required(args, "name")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", name):
            raise InputError("name must use letters, digits, _ or - and be at most 64 characters")
        region, plan, image = (_required(args, field) for field in ("region", "plan", "image"))
        count = int(args.get("count", 1))
        if count < 1 or count > 20:
            raise InputError("count must be between 1 and 20")

        if account["provider"] == "hetzner":
            available = {key for key, _ in await provider.plans(region, force=True)}
            if plan not in available:
                raise InputError("Hetzner plan is unavailable in this region; list plans again")

        # Resolve SSH keys if provided
        ssh_keys = args.get("ssh_keys") or []
        ssh_key_ids = args.get("ssh_key_ids") or []
        resolved_ssh = []

        if ssh_key_ids:
            for kid in ssh_key_ids:
                stored = store.ssh_key(int(kid))
                if stored:
                    resolved_ssh.append(stored)

        # Upload or adapt keys for specific provider if needed
        provider_keys = []
        if resolved_ssh:
            try:
                resolved = await provider.resolve_ssh_keys_for_instance(resolved_ssh)
                if resolved:
                    provider_keys.extend(resolved)
            except Exception as exc:
                log.warning("Failed resolving SSH keys for account %s: %s", account_id, exc)
        for raw_k in ssh_keys:
            provider_keys.append(raw_k)

        if count == 1:
            srv_name = name
            if account["provider"] == "linode":
                from providers import sanitize_linode_label
                srv_name = sanitize_linode_label(srv_name)
            elif not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", srv_name):
                raise InputError("name must use letters, digits, _ or - and be at most 64 characters")

            password = secrets.token_urlsafe(24)
            enable_ipv6 = bool(args.get("enable_ipv6", False))
            server = await provider.create_server(srv_name, region, plan, image, password,
                                                  auto_backup=account.get("auto_backup"),
                                                  ssh_keys=provider_keys if provider_keys else None,
                                                  enable_ipv6=enable_ipv6)
            store.set_server_pass(account_id, server["id"], server.get("root_password") or password)
            _delete_cache(store, "all_servers")
            return {"server": _server_public(server), "servers": [_server_public(server)], "created_count": 1, "password_stored": True}

        # Multiple server batch creation
        created_list = []
        enable_ipv6 = bool(args.get("enable_ipv6", False))
        for i in range(1, count + 1):
            if re.search(r"-\d+$", name):
                prefix = re.sub(r"-\d+$", "", name)
                inst_name = f"{prefix}-{i:02d}" if count >= 10 else f"{prefix}-{i}"
            else:
                inst_name = f"{name}-{i:02d}" if count >= 10 else f"{name}-{i}"

            if account["provider"] == "linode":
                from providers import sanitize_linode_label
                inst_name = sanitize_linode_label(inst_name)

            pwd = secrets.token_urlsafe(24)
            try:
                srv = await provider.create_server(inst_name, region, plan, image, pwd,
                                                      auto_backup=account.get("auto_backup"),
                                                      ssh_keys=provider_keys if provider_keys else None,
                                                      enable_ipv6=enable_ipv6)
                store.set_server_pass(account_id, srv["id"], srv.get("root_password") or pwd)
                created_list.append(_server_public(srv))
            except Exception as e:
                if not created_list:
                    raise
                log.warning("Batch creation stopped at %d: %s", i, e)
                break

        _delete_cache(store, "all_servers")
        return {"servers": created_list, "created_count": len(created_list), "requested_count": count,
                "server": created_list[0] if created_list else None, "password_stored": True}

    if operation == "assign_floating_ip":
        floating_id = _required(args, "floating_id")
        server_id = _required(args, "server_id")
        if account["provider"] == "hetzner":
            res = await provider.assign_hetzner_floating_ip(floating_id, server_id)
        elif account["provider"] == "vultr":
            res = await provider.attach_vultr_reserved_ip(floating_id, server_id)
        else:
            raise InputError(f"Floating IP assignment not supported on {account['provider']}")
        _delete_cache(store, "all_floating_ips")
        _delete_cache(store, "all_servers")
        return {"assigned": True, "floating_id": floating_id, "server_id": server_id, "result": res}

    if operation == "unassign_floating_ip":
        floating_id = _required(args, "floating_id")
        if account["provider"] == "hetzner":
            res = await provider.unassign_hetzner_floating_ip(floating_id)
        elif account["provider"] == "vultr":
            res = await provider.detach_vultr_reserved_ip(floating_id)
        else:
            raise InputError(f"Floating IP unassignment not supported on {account['provider']}")
        _delete_cache(store, "all_floating_ips")
        _delete_cache(store, "all_servers")
        return {"unassigned": True, "floating_id": floating_id, "result": res}

    if operation == "update_floating_ip":
        floating_id = _required(args, "floating_id")
        ip = args.get("ip")
        ptr = args.get("ptr")
        if account["provider"] == "hetzner" and ip and ptr:
            res = await provider.change_hetzner_floating_ip_ptr(floating_id, ip, ptr)
            _delete_cache(store, "all_floating_ips")
            return {"updated": True, "result": res}
        return {"updated": True}

    if operation in {"server", "server_password", "set_server_password", "reset_server_password",
                     "toggle_vultr_backups", "swap_linode_ips", "delete_server", "floating_ips", "power_server"}:
        server_id = _required(args, "server_id")
    else:
        server_id = args.get("server_id")

    if operation == "server":
        srv = await provider.server(server_id)
        srv_pub = _server_public(srv)
        srv_pub["account_id"] = account_id
        srv_pub["account_label"] = account.get("label", "")
        srv_pub["provider"] = account.get("provider", "")
        stored_pw = store.server_pass(account_id, server_id)
        if not stored_pw and srv.get("default_password"):
            store.set_server_pass(account_id, server_id, srv["default_password"])
            stored_pw = srv["default_password"]
        srv_pub["has_password"] = bool(stored_pw)
        attached_fips = await _floating(provider, server_id)
        primary_ips = []
        linode_networking = None
        if account.get("provider") == "hetzner":
            try:
                all_pips = await provider.hetzner_primary_ips()
                primary_ips = [p for p in all_pips if str(p.get("assignee_id")) == str(server_id)]
            except Exception:
                pass
        elif account.get("provider") == "linode":
            try:
                linode_networking = await provider.linode_instance_ips(server_id)
            except Exception:
                pass
        return {
            "server": srv_pub,
            "floating_ips": attached_fips,
            "primary_ips": primary_ips,
            "linode_networking": linode_networking,
        }

    if operation == "server_password":
        _confirm(args, "SHOW_PASSWORD")
        pw = store.server_pass(account_id, server_id)
        if not pw and account.get("provider") == "vultr":
            try:
                srv = await provider.server(server_id)
                pw = srv.get("default_password")
                if pw:
                    store.set_server_pass(account_id, server_id, pw)
            except Exception:
                pass
        return {"password": pw}

    if operation == "set_server_password":
        pw = _required(args, "password")
        store.set_server_pass(account_id, server_id, pw)
        return {"saved": True, "server_id": server_id}

    if operation == "reset_server_password":
        _confirm(args, "RESET_PASSWORD")
        if account["provider"] != "hetzner":
            raise InputError("reset_server_password is only supported for Hetzner Cloud")
        new_pw = await provider.reset_root_password(server_id)
        store.set_server_pass(account_id, server_id, new_pw)
        return {"password": new_pw, "server_id": server_id}

    if operation == "toggle_vultr_backups":
        if account["provider"] != "vultr":
            raise InputError("Auto-backup toggle is only available for Vultr")
        status = _required(args, "status").lower()
        if status not in {"enabled", "disabled"}:
            raise InputError("status must be 'enabled' or 'disabled'")
        await provider.set_vultr_backups(server_id, status)
        _delete_cache(store, "all_servers")
        return {"server_id": server_id, "status": status}

    if operation == "swap_linode_ips":
        _confirm(args, "SWAP_LINODE_IPS")
        if account["provider"] != "linode":
            raise InputError("IP swap is only supported for Linode")
        target_server_id = _required(args, "target_server_id")
        res = await provider.linode_swap_ips(server_id, target_server_id)
        _delete_cache(store, "all_servers")
        return {"swapped": True, "server_id": server_id, "target_server_id": target_server_id, "result": res}

    if operation == "delete_server":
        _confirm(args, "DELETE_SERVER")
        await provider.delete_server(server_id)
        store.delete_server_pass(account_id, server_id)
        _delete_cache(store, "all_servers")
        _delete_cache(store, "all_floating_ips")
        return {"deleted": True, "server_id": server_id}

    if operation == "floating_ips":
        return {"floating_ips": await _floating(provider, server_id)}

    if operation == "power_server":
        action = _required(args, "action").lower()
        if account["provider"] == "vultr":
            if action not in {"start", "halt", "reboot"}:
                raise InputError("action must be start, halt, or reboot")
            _confirm(args, action.upper())
            await provider.vultr_power(server_id, action)
        elif account["provider"] == "hetzner":
            if action not in {"start", "halt", "reboot", "poweron", "shutdown", "poweroff"}:
                raise InputError("action must be start, halt, or reboot")
            _confirm(args, action.upper())
            await provider.power_server(server_id, action)
        elif account["provider"] == "linode":
            if action not in {"start", "halt", "reboot", "boot", "shutdown"}:
                raise InputError("action must be start, halt, or reboot")
            _confirm(args, action.upper())
            await provider.power_server(server_id, action)
        else:
            raise InputError(f"power_server not supported for {account['provider']}")
        _delete_cache(store, "all_servers")
        return {"accepted": True, "action": action, "server_id": server_id}

    if operation == "create_floating_ip":
        _confirm(args, "CREATE_FLOATING_IP")
        if server_id and server_id != "0":
            server = await provider.server(server_id)
            if account["provider"] == "vultr":
                result = await provider.create_and_attach_vultr_floating_ip(
                    server_id, server["region"], f"cloudbot-{server_id[:24]}")
            elif account["provider"] == "hetzner":
                ip_type = _required(args, "ip_type")
                if ip_type not in {"ipv4", "ipv6"}:
                    raise InputError("ip_type must be ipv4 or ipv6")
                result = await provider.create_hetzner_floating_ip(
                    server_id, ip_type, f"cloudbot-{server_id}-{ip_type}-{secrets.token_hex(4)}")
            elif account["provider"] == "linode":
                raise InputError("Linode does not support ephemeral floating IPs. Use Linode IP Swap or IP Sharing via Akamai Cloud Manager.")
            else:
                raise InputError("floating IPs are supported for Vultr and Hetzner")
        else:
            # Standalone creation without attached server
            region = _required(args, "region")
            ip_type = args.get("ip_type", "ipv4")
            label = args.get("name", "floating-ip")
            if account["provider"] == "vultr":
                result = await provider.create_vultr_reserved_ip(region, ip_type="v4" if ip_type in ("v4", "ipv4") else "v6", label=label)
            elif account["provider"] == "hetzner":
                result = await provider.create_hetzner_floating_ip(server_id=None, ip_type=ip_type, name=label, home_location=region)
            elif account["provider"] == "linode":
                raise InputError("Linode does not support ephemeral floating IPs. Use Linode IP Swap or IP Sharing via Akamai Cloud Manager.")
            else:
                raise InputError("floating IPs are supported for Vultr and Hetzner")
        _delete_cache(store, "all_floating_ips")
        _delete_cache(store, "all_servers")
        return {"floating_ip": result, "configure_guest_os": account["provider"] == "hetzner"}

    if operation == "delete_floating_ip":
        _confirm(args, "DELETE_FLOATING_IP")
        floating_id = _required(args, "floating_id")
        if server_id and server_id != "0":
            attached = await _floating(provider, server_id)
            if not any(str(row.get("id")) == floating_id for row in attached):
                raise InputError("floating IP is not attached to the specified server")
        if account["provider"] == "vultr":
            await provider.delete_vultr_floating_ip(floating_id)
        elif account["provider"] == "hetzner":
            await provider.delete_hetzner_floating_ip(floating_id)
        else:
            raise InputError("floating IPs are supported for Vultr and Hetzner")
        _delete_cache(store, "all_floating_ips")
        _delete_cache(store, "all_servers")
        return {"deleted": True, "floating_id": floating_id}

    raise InputError("unknown operation")


def _dns_public(record):
    if not record:
        return None
    return {key: record.get(key) for key in ("id", "name", "content", "ttl", "proxied", "type")}
