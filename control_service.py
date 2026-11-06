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
from proxy_usage import ProxyUsage, TrafficLimitExceeded
from cloudflare import Cloudflare
from providers import Provider, region_country, country_code, country_flag, proxy_url, is_proxy_failure, account_suspension

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


def _normalize_proxy_value(value):
    """Validate and canonicalize a proxy before it reaches encrypted storage."""
    if value is None or not str(value).strip():
        return None
    try:
        return proxy_url(str(value).strip())
    except Exception as exc:
        raise InputError(f"Invalid proxy: {exc}") from None


OPERATIONS = {
    "sync_status": "Read automatic inventory sync status without calling providers",
    "accounts": "List configured cloud accounts without credentials",
    "account_info": "Read a provider account's billing and access details",
    "resource_limits": "Read provider resource limits, quotas, and current usage",
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
    "create_floating_ip": "Create and attach a Vultr, Hetzner, UpCloud, or CloudFerro address; confirm CREATE_FLOATING_IP",
    "delete_floating_ip": "Delete an attached floating IP; confirm DELETE_FLOATING_IP",
    "upsert_dns": "Create or repoint a Cloudflare A record; confirm UPSERT_DNS",
    # Extended operations for Hosting Dashboard:
    "all_servers": "List servers across all accounts with network and spec details",
    "all_floating_ips": "List all floating IPs across accounts with assignment status",
    "assign_floating_ip": "Assign an existing floating IP to a server",
    "unassign_floating_ip": "Unassign/detach a floating IP from its server",
    "update_floating_ip": "Update floating IP reverse DNS PTR or label",
    "upcloud_networking": "Read UpCloud server interfaces and IP addresses",
    "upcloud_add_interface_ip": "Add an IP to an UpCloud network interface; confirm ADD_INTERFACE_IP",
    "upcloud_remove_interface_ip": "Remove an IP from an UpCloud network interface; confirm REMOVE_INTERFACE_IP",
    "upcloud_delete_ip": "Delete an UpCloud IP address; confirm DELETE_FLOATING_IP",
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
    "set_account_note": "Set or update the note or memo for a cloud provider account",
    "update_account": "Rename an account and optionally verify and replace its API token",
    "proxy_availability": "Check available unallocated sessions for a provider in a specific country",
    "set_server_password": "Save or update stored root password for a server",
    "reset_server_password": "Reset root password on Hetzner and reboot; confirm RESET_PASSWORD",
    "toggle_vultr_backups": "Enable or disable auto-backups for a Vultr server",
    "swap_linode_ips": "Swap IPv4 addresses between two Linodes in the same region; confirm SWAP_LINODE_IPS",
    "activity_logs": "List operational activity and audit history (what happened)",
    "system_logs": "Read live system and service journal logs (what is happening)",
}

READ_OPERATIONS = frozenset({
    'sync_status', 'accounts', 'account_info', 'resource_limits', 'servers', 'server',
    'regions', 'plans', 'images', 'floating_ips', 'watch_status', 'tunnels',
    'dns_zones', 'dns_record', 'all_servers', 'all_floating_ips', 'server_password',
    'ssh_keys', 'check_all_accounts', 'hetzner_primary_ips', 'dns_records',
    'proxy_pool', 'test_account', 'test_proxy', 'proxy_providers', 'proxy_sessions',
    'parse_proxy_sessions', 'proxy_availability', 'upcloud_networking',
    'activity_logs', 'system_logs',
})


def _extract_session_ids_from_text(raw_text, template_username=None):
    if not raw_text:
        return []
    if isinstance(raw_text, list):
        raw_text = "\n".join(str(x) for x in raw_text)
    if 'gw.dataimpulse.com' in str(raw_text):
        from proxy_pool import import_format
        try:
            return import_format(raw_text)[1]
        except ValueError:
            return []

    # 1. Range pattern e.g. "1-50"
    m_range = re.fullmatch(r'(\d+)\s*-\s*(\d+)', str(raw_text).strip())
    if m_range:
        s_n, e_n = int(m_range.group(1)), int(m_range.group(2))
        if 0 <= s_n <= e_n and (e_n - s_n) <= 2000:
            return [str(i) for i in range(s_n, e_n + 1)]

    # 2. Template regex if provider username pattern provided
    tpl_regex = None
    if template_username and "{session}" in template_username:
        pattern = re.escape(template_username)
        pattern = pattern.replace(re.escape("{country}"), r"(?:[A-Za-z]{2}|[A-Za-z0-9_-]+?)")
        pattern = pattern.replace(re.escape("{session}"), r"(?P<session>[A-Za-z0-9_-]+)")
        try:
            tpl_regex = re.compile(pattern)
        except Exception:
            tpl_regex = None

    # 3. Normalize into candidate items (support newlines, semicolons, commas)
    normalized = str(raw_text).replace('\r\n', '\n').replace('\r', '\n').replace(';', '\n')
    raw_lines = normalized.split('\n')
    items = []
    for line in raw_lines:
        line = line.strip()
        if not line:
            continue
        if ',' in line:
            parts = line.split(',')
            for p in parts:
                p = p.strip()
                if p:
                    items.append(p)
        else:
            items.append(line)

    found = []
    stopwords = {'http', 'https', 'socks4', 'socks5', 'sample', 'proxy', 'swiftproxy', 'webshare', 'true', 'false', 'none', 'null'}

    for item in items:
        # Strip comments starting with # or // (avoid stripping :// in URLs)
        item = re.sub(r'(?<!:)(?<!/)//.*$|#.*$', '', item).strip()
        # Skip standalone numbering lines (e.g. "1", "2.", "[3]", "#4")
        if re.fullmatch(r'#?\[?\d+\]?[.):]?\s*', item):
            continue
        # Strip leading numbers on a proxy line
        item = re.sub(r'^\s*#?\[?\d+\]?[.):\s]+\s*(?=[a-zA-Z0-9]+://|[a-zA-Z0-9.-]+:\d+|[a-zA-Z0-9_-]+)', '', item).strip()
        # Strip surrounding quotes
        item = item.strip('\"\'')
        if not item:
            continue

        # If it has spaces and no proxy delimiters (':', '@', '://'), it is commentary/prose - skip it
        if ' ' in item and not any(c in item for c in (':', '@', '://')):
            continue

        # Take first token if inline note attached to proxy
        first_token = item.split()[0] if ' ' in item else item

        # Extract user candidate
        user_candidate = None
        target = first_token
        if '@' in target:
            auth_part = target.split('@')[0]
            if '://' in auth_part:
                auth_part = auth_part.split('://', 1)[1]
            if ':' in auth_part:
                user_candidate = auth_part.split(':', 1)[0]
            else:
                user_candidate = auth_part
        elif target.count(':') >= 2:
            parts = target.split(':')
            if len(parts) >= 4:
                user_candidate = parts[2]
            elif len(parts) == 3:
                user_candidate = parts[2] if parts[1].isdigit() else parts[1]

        target_text = user_candidate or target

        # Step A: Template regex match
        if tpl_regex:
            m = tpl_regex.search(target_text) or tpl_regex.search(target)
            if m:
                found.append(m.group("session"))
                continue

        # Step B: SwiftProxy and standard sid / ssid heuristic
        m = re.search(r'(?:ssid|sid|session)[_:= -]([a-zA-Z0-9_-]+?)(?:_(?:time|life|sst)|-(?:sst|time|life)|[:@/\s,;]|$)', target_text, re.IGNORECASE)
        if not m:
            m = re.search(r'(?:ssid|sid|session)[_:= -]([a-zA-Z0-9_-]+)', target_text, re.IGNORECASE)
        if m:
            sid = m.group(1).strip('_-')
            if sid:
                found.append(sid)
                continue

        # Step C: Country / zone tag heuristic
        if user_candidate and user_candidate != target:
            mc = re.search(r'(?:country|zone|region)[_-][A-Za-z]{2}[_-]([a-zA-Z0-9_-]+)', user_candidate, re.IGNORECASE)
            if mc:
                sid = mc.group(1).strip('_-')
                if sid:
                    found.append(sid)
                    continue

        # Step D: Raw session token (single identifier without host/colons/slashes/spaces)
        if ' ' not in target and re.fullmatch(r'[A-Za-z0-9_-]{1,128}', target):
            if target.lower() not in stopwords and (not target.isdigit() or len(target) >= 2):
                found.append(target)

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
        "note": account.get("note") or "",
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
    if provider.provider == "upcloud":
        # UpCloud's account IP inventory also includes primary addresses;
        # this operation is intentionally limited to floating addresses.
        return [row for row in await provider.upcloud_ip_addresses(server_id)
                if row.get("floating")]
    if provider.provider == "cloudferro":
        return await provider.cloudferro_floating_ips(server_id)
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
        if k in {'all_servers', 'all_floating_ips', 'all_billing'} or k.startswith('primary_ips:'):
            saved = _get_cache(store, k)
            if saved is not None:
                _set_cache(store, 'saved:' + k, saved)
        store.delete_cache(k)


def _record_activity(store, action, provider="", target="", status="success", details="", error="", source="web"):
    if hasattr(store, "record_activity"):
        try:
            store.record_activity(action, provider=provider, target=target, status=status, details=details, error=error, source=source)
        except Exception:
            pass


def _snapshot_cache(store, key):
    value = _get_cache(store, key)
    return value if value is not None else _get_cache(store, 'saved:' + key)


def _scope_accounts(store, args):
    accounts = store.accounts()
    if args.get('account_id') is not None:
        account = _account(store, args)
        accounts = [account]
    if args.get('provider'):
        name = str(args['provider']).lower()
        if name not in {'hetzner', 'vultr', 'linode', 'upcloud', 'cloudferro'}:
            raise InputError('unknown cloud provider')
        accounts = [a for a in accounts if a['provider'] == name]
    return accounts


def _row_account(row, field):
    return str((row.get('account') or {}).get('id') if field == 'accounts' else row.get('account_id'))


def _scoped_snapshot(snapshot, field, accounts):
    snapshot = snapshot or {}
    ids = {str(a['id']) for a in accounts}
    return {**snapshot, field: [r for r in snapshot.get(field, []) if _row_account(r, field) in ids],
            'account_errors': {k: v for k, v in snapshot.get('account_errors', {}).items() if str(k) in ids}}


def _save_scoped_snapshot(store, key, field, result, accounts):
    old = _snapshot_cache(store, key) or {}
    target = {str(a['id']) for a in accounts}
    active = {str(a['id']) for a in store.accounts()}
    failed = set(result.get('account_errors', {}))
    retained_failures = failed - {_row_account(r, field) for r in result[field]}
    rows = [r for r in old.get(field, []) if _row_account(r, field) in active and
            (_row_account(r, field) not in target or _row_account(r, field) in retained_failures)]
    rows += result[field]
    errors = {k: v for k, v in old.get('account_errors', {}).items() if str(k) in active and str(k) not in target}
    errors.update(result.get('account_errors', {}))
    combined = {**result, field: rows, 'account_errors': errors}
    _set_cache(store, key, combined)
    return _scoped_snapshot(combined, field, accounts)


def _safe_error(exc, account=None):
    """Return a provider error with account credentials removed."""
    message = str(exc)
    if account:
        for key in ("token", "proxy", "proxy_request"):
            value = account.get(key)
            if value:
                message = message.replace(str(value), "[redacted]")
    return message


async def execute(operation, args, store):
    result = await _execute(operation, args, store)
    if operation not in READ_OPERATIONS and hasattr(store, 'request_sync'):
        # The shared SQLite queue also reaches the worker from MCP and Telegram.
        account_id = args.get('account_id')
        if operation == 'add_account':
            account_id = result.get('id')
        if operation == 'delete_account':
            account_id = None
        store.request_sync(account_id)
    return result


async def _execute(operation, args, store):
    """Execute one documented operation with validated, JSON-safe arguments."""
    if operation == 'sync_status':
        return {**(_get_cache(store, 'sync_state') or {}),
                'pending': bool(store.pending_sync()) if hasattr(store, 'pending_sync') else False}
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
        if provider_name not in ("linode", "vultr", "hetzner", "upcloud", "cloudferro"):
            raise InputError("provider must be linode, vultr, hetzner, upcloud, or cloudferro")
        token = _required(args, "token")
        proxy = _normalize_proxy_value(args.get("proxy"))
        proxy_family = args.get("proxy_family") or "default"
        auto_backup = args.get("auto_backup") or "disabled"
        region = _normalize_country(args.get("region"))
        note = str(args.get("note") or "").strip()
        proxy_provider_id = args.get("proxy_provider_id")
        if proxy_provider_id and not region:
            raise InputError("Account country / region is required to allocate from proxy providers")

        add_params = store.add_account.__code__.co_varnames if hasattr(store, "add_account") else ()
        kwargs = {"proxy": proxy, "proxy_family": proxy_family, "auto_backup": auto_backup}
        if "region" in add_params:
            kwargs["region"] = region
        if "note" in add_params:
            kwargs["note"] = note
        acc_id = store.add_account(label, provider_name, token, **kwargs)

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
        resp = {"id": acc_id, "label": label, "provider": provider_name, "region": region, "note": note}
        if allocated_info:
            resp["allocated_proxy"] = {
                "country": allocated_info.get("country", region),
                "session": allocated_info.get("session"),
                "proxy_masked": "configured",
            }
        _record_activity(store, "ADD_ACCOUNT", provider=provider_name, target=label, status="success", details=f"Region: {region or 'none'}")
        return resp

    if operation == "delete_account":
        _confirm(args, "DELETE_ACCOUNT")
        account_id = int(_required(args, "account_id"))
        n = store.delete_account(account_id)
        _delete_cache(store, "all_servers")
        _delete_cache(store, "all_floating_ips")
        _delete_cache(store, "all_billing")
        _delete_cache(store, f"primary_ips:{account_id}")
        _record_activity(store, "DELETE_ACCOUNT", provider="", target=str(account_id), status="success" if n > 0 else "failed", details=f"Deleted account ID {account_id}")
        return {"deleted": n > 0, "account_id": account_id}

    if operation == "check_all_accounts":
        accs = _scope_accounts(store, args)
        force_refresh = bool(args.get("refresh") or args.get("force"))
        if not force_refresh:
            cached = _snapshot_cache(store, 'all_billing') if args.get('cached_only') else _get_cache(store, 'all_billing')
            if cached is not None and isinstance(cached, dict) and "accounts" in cached:
                return _scoped_snapshot(cached, 'accounts', accs) if args.get('cached_only') or args.get('provider') or args.get('account_id') else cached
        if args.get('cached_only'):
            return _scoped_snapshot({}, 'accounts', accs)

        async def _check_one(acc):
            try:
                p = Provider(acc)
                info = await p.account_info()
                ident = await p.whoami()
                item = {
                    "account": _account_public(acc, store),
                    "status": "ok",
                    "info": info,
                    "identity": ident,
                }
                if acc["provider"] == "cloudferro":
                    item["limits"] = await p.cloudferro_resource_limits()
                item.update(account_suspension(await p.list_servers(), info))
                return item
            except Exception as exc:
                return {
                    "account": _account_public(acc, store),
                    "status": "error",
                    "error": _safe_error(exc, acc),
                }

        results = await asyncio.gather(*[_check_one(a) for a in accs], return_exceptions=True)
        res = {"accounts": [r for r in results if isinstance(r, dict)], "cached_at": time.time()}
        return _save_scoped_snapshot(store, 'all_billing', 'accounts', res, accs)

    if operation == "test_account":
        account = _account(store, args)
        p = Provider(account)
        start_t = time.time()
        try:
            ident = await p.whoami()
            info = await p.account_info()
            health = account_suspension(await p.list_servers(), info)
            latency_ms = round((time.time() - start_t) * 1000, 1)
            return {
                "status": "ok",
                "account": _account_public(account, store),
                "identity": ident,
                "info": info,
                "latency_ms": latency_ms,
                **health,
            }
        except Exception as exc:
            return {
                "status": "error",
                "account": _account_public(account, store),
                "error": _safe_error(exc, account),
            }

    if operation == "set_account_region":
        account = _account(store, args)
        region = _normalize_country(args.get("region"))
        if hasattr(store, "set_account_region"):
            store.set_account_region(account["id"], region)
        _delete_cache(store, "all_billing")
        _delete_cache(store, "all_servers")
        _delete_cache(store, "all_floating_ips")
        updated = store.account(account["id"])
        return {"updated": True, "account": _account_public(updated, store)}

    if operation == "update_account":
        account = _account(store, args)
        label = str(args.get("label", account["label"]) or "").strip()
        if not label:
            raise InputError("Account name is required")
        token = str(args.get("token") or "").strip() or None
        if token is not None:
            candidate = {**account, "token": token}
            try:
                await Provider(candidate).account_info()
            except Exception as exc:
                message = _safe_error(exc, candidate)
                message = _safe_error(Exception(message), account)
                raise InputError(f"Replacement API token could not be verified: {message}") from None
        store.update_account(account["id"], label, token)
        for key in ("all_billing", "all_servers", "all_floating_ips", f"primary_ips:{account['id']}"):
            _delete_cache(store, key)
        _record_activity(store, "UPDATE_ACCOUNT", provider=account["provider"],
                         target=str(account["id"]), details="API token replaced" if token else "Account renamed")
        return {"updated": True, "account": _account_public(store.account(account["id"]), store)}

    if operation == "set_account_note":
        account = _account(store, args)
        note = str(args.get("note") or "").strip()
        if hasattr(store, "set_account_note"):
            store.set_account_note(account["id"], note)
        _delete_cache(store, "all_billing")
        _delete_cache(store, "all_servers")
        _delete_cache(store, "all_floating_ips")
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
        _delete_cache(store, "all_servers")
        _delete_cache(store, "all_floating_ips")
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
        proxy = _normalize_proxy_value(args.get("proxy"))
        proxy_family = args.get("proxy_family") or "default"
        store.set_proxy(account["id"], proxy, proxy_family=proxy_family)
        if "region" in args and hasattr(store, "set_account_region"):
            store.set_account_region(account["id"], _normalize_country(args["region"]))
        _delete_cache(store, "all_billing")
        _delete_cache(store, "all_servers")
        _delete_cache(store, "all_floating_ips")
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
        meter = ProxyUsage(p_url)
        start_t = time.time()
        max_attempts = 4
        last_exc = None
        for attempt in range(1, max_attempts + 1):
            meter.ensure_available()
            try:
                headers = {"User-Agent": "Mozilla/5.0"}
                is_socks = bool(p_url) and p_url.startswith(("socks5", "socks4"))
                timeout = aiohttp.ClientTimeout(total=90, connect=45, sock_read=60)
                if is_socks:
                    try:
                        from aiohttp_socks import ProxyConnector
                        conn = ProxyConnector.from_url(p_url)
                        async with aiohttp.ClientSession(timeout=timeout, connector=conn, trace_configs=meter.trace_configs()) as s:
                            async with s.get("https://api.ipify.org?format=json", headers=headers) as r:
                                data = await meter.json(r)
                    except ImportError:
                        raise InputError("aiohttp-socks is required for SOCKS proxy testing")
                else:
                    async with aiohttp.ClientSession(timeout=timeout, trace_configs=meter.trace_configs()) as s:
                        async with s.get("https://api.ipify.org?format=json", proxy=p_url, headers=headers) as r:
                            data = await meter.json(r)
                latency_ms = round((time.time() - start_t) * 1000, 1)
                return {"status": "ok", "ip": data.get("ip"), "latency_ms": latency_ms}
            except (InputError, TrafficLimitExceeded):
                raise
            except Exception as exc:
                last_exc = exc
                if attempt < max_attempts:
                    await asyncio.sleep(0.5 * attempt)
                    continue
                err_str = str(last_exc)
                if not err_str.lower().startswith("proxy failed"):
                    err_str = f"Proxy failed: {err_str}"
                return {"status": "error", "error": err_str}

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
            p['identity_kind'] = 'port' if tpl.get('port') == '{port}' else 'session'
            p['usage_limit_gb'] = p.get('usage_limit_bytes', 0) / 1_000_000_000
            p['usage_gb'] = p.get('usage_bytes', 0) / 1_000_000_000
            p['usage_exhausted'] = bool(p.get('usage_limit_bytes') and p.get('usage_bytes', 0) >= p['usage_limit_bytes'])
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
        template = args.get("template")
        if template is None or isinstance(template, bool) or (isinstance(template, str) and not template.strip()):
            raise InputError("template is required")
        ids_input = args.get("session_ids") or ""
        from proxy_pool import session_ids, import_format, proxy_string, ProxyPoolError

        extra_ids = []
        if isinstance(template, dict):
            tpl_dict = template
        elif isinstance(template, str):
            tpl_str = template.strip()
            scheme = args.get("scheme", "http").lower()
            if "://" not in tpl_str and not tpl_str.startswith(("http://", "https://", "socks4://", "socks5://")):
                tpl_str = f"{scheme}://{tpl_str}"
            tpl_dict, extra_ids = import_format(tpl_str)
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

        combined_ids = list(dict.fromkeys(raw_ids + extra_ids))
        ids = session_ids("\n".join(combined_ids))
        if not ids:
            raise InputError("At least one valid session ID is required")

        options = {'family': args.get('family', 'default')}
        if 'usage_limit_gb' in args:
            options['usage_limit_gb'] = args['usage_limit_gb']
        pid = store.add_proxy_provider(label, tpl_dict, ids, **options)
        return {"id": pid, "label": label, "sessions_count": len(ids)}

    if operation == "update_proxy_provider":
        pid = int(_required(args, "provider_id"))
        updated = {}
        if 'usage_limit_gb' in args or args.get('reset_usage'):
            store.configure_proxy_usage(pid, limit_gb=args.get('usage_limit_gb'), reset=bool(args.get('reset_usage')))
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
        detected_template = None
        detected_country = None
        suggested_label = None
        if 'gw.dataimpulse.com' in str(raw):
            from proxy_pool import import_format
            try:
                detected_template, extracted = import_format(raw)
                return {'session_ids': extracted, 'count': len(extracted), 'identity_kind': 'port',
                        'detected_template': detected_template, 'suggested_label': 'DataImpulse'}
            except ValueError as exc:
                raise InputError(str(exc)) from None
        try:
            from proxy_pool import components, inferred_username
            for line in str(raw).splitlines():
                line = line.strip()
                if not line or line.startswith(('#', '//')):
                    continue
                line = line.split()[0].rstrip(',;').strip('\"\'')
                if ':' in line:
                    try:
                        comp = components(line)
                        inf = inferred_username(comp.get("username", ""))
                        if inf:
                            tpl_user, c_code, _ = inf
                            detected_country = c_code
                            detected_template = {
                                "scheme": comp.get("scheme", "http"),
                                "host": comp.get("host", ""),
                                "port": comp.get("port", 80),
                                "username": tpl_user,
                                "password": comp.get("password", ""),
                                "auth": comp.get("auth", True),
                            }
                            host_str = comp.get("host", "")
                            if "swiftproxy" in host_str.lower():
                                suggested_label = f"SwiftProxy Pool ({host_str})"
                            elif "webshare" in host_str.lower():
                                suggested_label = f"Webshare Pool ({host_str})"
                            elif host_str:
                                suggested_label = f"Proxy Pool ({host_str})"
                            break
                    except Exception:
                        pass
        except Exception:
            pass
        return {
            "session_ids": extracted,
            "count": len(extracted),
            "detected_template": detected_template,
            "detected_country": detected_country,
            "suggested_label": suggested_label,
        }

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
                await asyncio.wait_for(p.whoami(), timeout=120)
            except Exception as e:
                error_reason = str(e)
                if not acc.get("proxy") or not is_proxy_failure(e):
                    skipped.append({"id": acc["id"], "label": acc["label"],
                                    "reason": "Account/API error; proxy replacement is not indicated",
                                    "error": error_reason})
                    continue
                is_broken = True

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
                    ident = await asyncio.wait_for(p_new.whoami(), timeout=120)
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
                    log.warning("Auto-heal failed for account %s on provider %s: %s",
                                acc["id"], pid, _safe_error(alloc_err, acc))
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
        accs = _scope_accounts(store, args)
        force_refresh = bool(args.get("refresh") or args.get("force"))
        if not force_refresh:
            cached = _snapshot_cache(store, 'all_servers') if args.get('cached_only') else _get_cache(store, 'all_servers')
            if cached is not None and isinstance(cached, dict) and "servers" in cached:
                return _scoped_snapshot(cached, 'servers', accs) if args.get('cached_only') or args.get('provider') or args.get('account_id') else cached
        if args.get('cached_only'):
            return _scoped_snapshot({}, 'servers', accs)
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
                elif acc["provider"] == "upcloud":
                    try:
                        for f in await p.upcloud_ip_addresses():
                            s_id = str(f.get("server_id") or "")
                            if s_id and f.get("floating"):
                                f_map.setdefault(s_id, []).append(f)
                    except Exception as exc:
                        # Keep the server row, but surface stale IP inventory
                        # so callers can retry and understand the partial view.
                        log.warning("Failed listing UpCloud IPs for account %s: %s",
                                    acc["id"], _safe_error(exc, acc))
                        account_errors[str(acc["id"])] = _safe_error(exc, acc)
                elif acc["provider"] == "cloudferro":
                    try:
                        for f in await p.cloudferro_floating_ips():
                            s_id = str(f.get("server_id") or "")
                            if s_id:
                                f_map.setdefault(s_id, []).append(f)
                    except Exception as exc:
                        account_errors[str(acc["id"])] = _safe_error(exc, acc)

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
                log.warning("Failed listing servers for account %s: %s",
                            acc["id"], _safe_error(exc, acc))
                account_errors[str(acc["id"])] = _safe_error(exc, acc)
                return []

        gathered = await asyncio.gather(*[_fetch_acc_servers(a) for a in accs], return_exceptions=True)
        servers = []
        for g in gathered:
            if isinstance(g, list):
                servers.extend(g)
        result = {"servers": servers, "account_errors": account_errors, "cached_at": time.time()}
        return _save_scoped_snapshot(store, 'all_servers', 'servers', result, accs)

    if operation == "all_floating_ips":
        accs = _scope_accounts(store, args)
        force_refresh = bool(args.get("refresh") or args.get("force"))
        if not force_refresh:
            cached = _snapshot_cache(store, 'all_floating_ips') if args.get('cached_only') else _get_cache(store, 'all_floating_ips')
            if cached is not None and isinstance(cached, dict) and "floating_ips" in cached:
                return _scoped_snapshot(cached, 'floating_ips', accs) if args.get('cached_only') or args.get('provider') or args.get('account_id') else cached
        if args.get('cached_only'):
            return _scoped_snapshot({}, 'floating_ips', accs)

        account_errors = {}

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
                elif acc["provider"] == "upcloud":
                    for f in await p.upcloud_ip_addresses():
                        if not f.get("floating"):
                            continue
                        srv_id = str(f.get("server_id") or "") or None
                        rows.append({
                            **f,
                            "id": f.get("address"),
                            "account_id": acc["id"],
                            "account_label": acc["label"],
                            "provider": "upcloud",
                            "ip": f.get("address"),
                            "type": f.get("family"),
                            "name": "",
                            "server_id": srv_id,
                            "region": f.get("zone"),
                            "country": region_country("upcloud", f.get("zone")),
                            "dns_ptr": f.get("ptr"),
                            "status": "assigned" if srv_id else "unassigned",
                            "protection": False,
                        })
                elif acc["provider"] == "cloudferro":
                    for f in await p.cloudferro_floating_ips():
                        rows.append({**f, "account_id": acc["id"], "account_label": acc["label"],
                                     "provider": "cloudferro", "name": "", "region": "waw3-1",
                                     "country": "PL", "status": f.get("status", "unassigned"),
                                     "server_id": f.get("server_id")})
            except Exception as exc:
                log.warning("Failed listing floating IPs for account %s: %s",
                            acc["id"], _safe_error(exc, acc))
                account_errors[str(acc["id"])] = _safe_error(exc, acc)
            return rows

        gathered = await asyncio.gather(*[_fetch_acc_fips(a) for a in accs], return_exceptions=True)
        all_fips = []
        for g in gathered:
            if isinstance(g, list):
                all_fips.extend(g)
        result = {"floating_ips": all_fips, "account_errors": account_errors,
                  "cached_at": time.time()}
        return _save_scoped_snapshot(store, 'all_floating_ips', 'floating_ips', result, accs)

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
        providers_list = []
        for prov in store.proxy_providers():
            prov = dict(prov)
            if isinstance(prov.get("template"), dict):
                prov["template"] = {k: ("***" if k in ("username", "password") else v)
                                    for k, v in prov["template"].items()}
            providers_list.append(prov)
        claims = [dict(c) for c in store.con.execute("SELECT account_id, provider_id, country, session_id, expires_at FROM proxy_claims ORDER BY rowid DESC LIMIT 50")]
        return {"providers": providers_list, "recent_claims": claims}

    # ---- System and Activity Logs --------------------------------------
    if operation == "activity_logs":
        limit = int(args.get("limit") or 100)
        action = args.get("action")
        provider_filter = args.get("provider")
        status_filter = args.get("status")
        items = store.get_activity_logs(limit=limit, action=action, provider=provider_filter, status=status_filter) if hasattr(store, "get_activity_logs") else []
        return {"activity_logs": items, "count": len(items)}

    if operation == "system_logs":
        service = str(args.get("service") or "all").strip().lower()
        lines = int(args.get("lines") or 150)
        lines = max(10, min(lines, 500))
        level_filter = str(args.get("level") or "").strip().lower()

        unit_map = {
            "all": ["-u", "cloudbot", "-u", "cloudbot-control-api", "-u", "probeapi"],
            "cloudbot": ["-u", "cloudbot"],
            "control_api": ["-u", "cloudbot-control-api"],
            "probeapi": ["-u", "probeapi"],
        }
        cmd_units = unit_map.get(service, ["-u", "cloudbot", "-u", "cloudbot-control-api", "-u", "probeapi"])
        cmd = ["journalctl", *cmd_units, "-n", str(lines), "--no-pager", "-o", "short-iso"]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            raw_text = stdout.decode("utf-8", errors="replace")
            log_entries = []
            for line in raw_text.splitlines():
                if not line.strip():
                    continue
                parts = line.split(" ", 3)
                ts = parts[0] if len(parts) > 0 else ""
                host = parts[1] if len(parts) > 1 else ""
                proc_info = parts[2] if len(parts) > 2 else ""
                msg = parts[3] if len(parts) > 3 else line
                lower_line = line.lower()
                lvl = "info"
                if "error" in lower_line or "exception" in lower_line or "fatal" in lower_line or "critical" in lower_line or "traceback" in lower_line:
                    lvl = "error"
                elif "warn" in lower_line or "warning" in lower_line:
                    lvl = "warning"
                elif "debug" in lower_line:
                    lvl = "debug"

                if level_filter and level_filter != "all" and lvl != level_filter:
                    continue

                log_entries.append({
                    "raw": line,
                    "ts": ts,
                    "host": host,
                    "process": proc_info,
                    "message": msg,
                    "level": lvl,
                })
            return {"logs": log_entries, "service": service, "lines_requested": lines, "count": len(log_entries)}
        except Exception as exc:
            log.warning("system_logs journalctl read failed: %s", exc)
            return {
                "logs": [
                    {
                        "raw": f"{time.strftime('%Y-%m-%dT%H:%M:%S%z')} local cloudbot[info]: Journalctl standby ({exc})",
                        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                        "host": "localhost",
                        "process": "cloudbot",
                        "message": f"Journalctl standby ({exc})",
                        "level": "info",
                    }
                ],
                "service": service,
                "lines_requested": lines,
                "count": 1,
            }

    # ---- Cloudflare DNS ------------------------------------------------
    if operation in {"dns_zones", "dns_record", "dns_records", "upsert_dns", "delete_dns_record"}:
        if operation == 'dns_zones' and args.get('cached_only'):
            return _get_cache(store, 'dns_zones', {'zones': []})
        token = store.cf_token()
        if not token:
            if operation == "dns_zones":
                return {"zones": [], "configured": False}
            raise InputError("Cloudflare token is not configured")
        cf = Cloudflare(token)

        if operation == "dns_zones":
            result = {"zones": [{"id": zid, "name": name} for zid, name in await cf.zones()]}
            _set_cache(store, 'dns_zones', result)
            return result

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
    if operation == 'hetzner_primary_ips' and args.get('cached_only'):
        account = _account(store, args)
        if account['provider'] != 'hetzner':
            raise InputError('Primary IPs are only supported on Hetzner')
        return _snapshot_cache(store, f"primary_ips:{account['id']}") or {'primary_ips': []}

    account = _account(store, args)
    provider = Provider(account)
    account_id = account["id"]

    if operation == "account_info":
        result = {"account": _account_public(account), "info": await provider.account_info(),
                  "identity": await provider.whoami()}
        if account["provider"] == "cloudferro":
            result["limits"] = await provider.cloudferro_resource_limits()
        return result

    if operation == "resource_limits":
        if account["provider"] != "cloudferro":
            raise InputError("resource_limits is currently supported for CloudFerro")
        return await provider.cloudferro_resource_limits()

    # UpCloud exposes interface operations that have no equivalent in the
    # other adapters. Keep these names explicit so callers cannot accidentally
    # pass an integer provider ID where an address/UUID string is required.
    if operation == "upcloud_networking":
        if account["provider"] != "upcloud":
            raise InputError("upcloud_networking is only supported for UpCloud")
        sid = _required(args, "server_id")
        return {"server_id": sid, "networking": await provider.upcloud_networking(sid)}

    if operation == "upcloud_add_interface_ip":
        if account["provider"] != "upcloud":
            raise InputError("upcloud_add_interface_ip is only supported for UpCloud")
        _confirm(args, "ADD_INTERFACE_IP")
        sid = _required(args, "server_id")
        interface_index = _required(args, "interface_index")
        family = args.get("family") or "IPv4"
        address = args.get("address")
        result = await provider.add_upcloud_interface_ip(
            sid, int(interface_index), address=address, family=family,
            force=bool(args.get("force")))
        _delete_cache(store, "all_servers")
        _delete_cache(store, "all_floating_ips")
        return {"added": True, "server_id": sid, "interface_index": int(interface_index),
                "result": result}

    if operation == "upcloud_remove_interface_ip":
        if account["provider"] != "upcloud":
            raise InputError("upcloud_remove_interface_ip is only supported for UpCloud")
        _confirm(args, "REMOVE_INTERFACE_IP")
        sid = _required(args, "server_id")
        interface_index = _required(args, "interface_index")
        address = _required(args, "address")
        result = await provider.remove_upcloud_interface_ip(sid, int(interface_index), address)
        _delete_cache(store, "all_servers")
        _delete_cache(store, "all_floating_ips")
        return {"removed": True, "server_id": sid, "interface_index": int(interface_index),
                "address": address, "result": result}

    if operation == "upcloud_delete_ip":
        if account["provider"] != "upcloud":
            raise InputError("upcloud_delete_ip is only supported for UpCloud")
        _confirm(args, "DELETE_FLOATING_IP")
        address = _required(args, "address")
        result = await provider.delete_upcloud_ip(address)
        _delete_cache(store, "all_servers")
        _delete_cache(store, "all_floating_ips")
        return {"deleted": True, "address": address, "result": result}

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
        try:
            res = await provider.regions(force=force)
        except Exception:
            # Preserve a known-good catalog across transient refresh errors.
            stored = _get_cache(store, cache_key)
            if isinstance(stored, dict) and "regions" in stored:
                return stored
            raise
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
        region = args.get("region")
        # UpCloud templates may be zone-specific; keep each zone's catalog
        # distinct so the deployment wizard never reuses incompatible images.
        cache_suffix = (f":{region}" if account["provider"] == "upcloud" else "")
        cache_key = f"images:{account['provider']}:{account['id']}{cache_suffix}"
        if not force:
            cached = _get_op_cache(cache_key)
            if cached is not None:
                return cached
            stored = _get_cache(store, cache_key)
            if stored is not None and isinstance(stored, dict) and "images" in stored:
                _set_op_cache(cache_key, stored, ttl=86400)
                return stored
        try:
            res = await provider.images(region=region, force=force)
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
        if args.get('cached_only'):
            return {'primary_ips': []}
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
        use_vault_keys = args.get("use_vault_keys")

        all_vault = store.ssh_keys()
        vault_by_id = {k["id"]: k for k in all_vault}
        vault_by_name = {k["name"]: k for k in all_vault}

        # If no explicit keys provided and use_vault_keys not explicitly disabled, use vault keys
        if not ssh_keys and not ssh_key_ids and (use_vault_keys is None or use_vault_keys):
            ssh_key_ids = [k["id"] for k in all_vault]

        resolved_ssh = []
        if ssh_key_ids:
            for kid in ssh_key_ids:
                try:
                    kid_int = int(kid)
                    stored = vault_by_id.get(kid_int) or store.ssh_key(kid_int)
                    if stored:
                        resolved_ssh.append(stored)
                except (ValueError, TypeError):
                    pass

        raw_keys_to_pass = []
        for raw_k in ssh_keys:
            if not raw_k:
                continue
            raw_str = str(raw_k).strip()
            if raw_str in vault_by_name:
                resolved_ssh.append(vault_by_name[raw_str])
            elif raw_str.isdigit() and int(raw_str) in vault_by_id:
                resolved_ssh.append(vault_by_id[int(raw_str)])
            elif raw_str.startswith(("ssh-", "ecdsa-")):
                if account["provider"] in ("hetzner", "vultr"):
                    resolved_ssh.append({"id": 0, "name": f"auto-{secrets.token_hex(4)}", "public_key": raw_str})
                else:
                    raw_keys_to_pass.append(raw_str)
            else:
                raw_keys_to_pass.append(raw_str)

        # Deduplicate resolved_ssh by public key
        seen_pubs = set()
        deduped_resolved = []
        for item in resolved_ssh:
            pub = item.get("public_key")
            if pub and pub not in seen_pubs:
                seen_pubs.add(pub)
                deduped_resolved.append(item)
            elif not pub and item not in deduped_resolved:
                deduped_resolved.append(item)

        # Upload or adapt keys for specific provider if needed
        provider_keys = []
        if deduped_resolved:
            try:
                resolved = await provider.resolve_ssh_keys_for_instance(deduped_resolved)
                if resolved:
                    provider_keys.extend(resolved)
            except Exception as exc:
                log.warning("Failed resolving SSH keys for account %s: %s", account_id, exc)
        for raw_k in raw_keys_to_pass:
            if raw_k not in provider_keys:
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
            returned_password = server.get("root_password")
            # UpCloud may not return a password for cloud-init/SSH-only
            # templates.  The generated fallback was never sent to that API,
            # so storing it would create unusable credentials in the vault.
            stored_password = returned_password or (None if account["provider"] == "upcloud" else password)
            if stored_password:
                store.set_server_pass(account_id, server["id"], stored_password)
            _delete_cache(store, "all_servers")
            _record_activity(store, "CREATE_SERVER", provider=account.get("provider", ""),
                                  target=server.get("name") or srv_name, status="success",
                                  details=f"Plan: {plan}, Region: {region}, Image: {image}")
            return {"server": _server_public(server), "servers": [_server_public(server)], "created_count": 1,
                    "password_stored": bool(stored_password)}

        # Multiple server batch creation
        created_list = []
        password_stored = False
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
                returned_password = srv.get("root_password")
                stored_password = returned_password or (None if account["provider"] == "upcloud" else pwd)
                if stored_password:
                    store.set_server_pass(account_id, srv["id"], stored_password)
                    password_stored = True
                created_list.append(_server_public(srv))
            except Exception as e:
                if not created_list:
                    raise
                log.warning("Batch creation stopped at %d: %s", i, e)
                break

        _delete_cache(store, "all_servers")
        _record_activity(store, "CREATE_SERVER_BATCH", provider=account.get("provider", ""),
                              target=f"{name} ({len(created_list)}/{count})",
                              status="success" if len(created_list) == count else "partial",
                              details=f"Created {len(created_list)} of {count} servers. Plan: {plan}, Region: {region}")
        return {"servers": created_list, "created_count": len(created_list), "requested_count": count,
                "server": created_list[0] if created_list else None,
                "password_stored": password_stored}

    if operation == "assign_floating_ip":
        floating_id = _required(args, "floating_id")
        server_id = _required(args, "server_id")
        if account["provider"] == "hetzner":
            res = await provider.assign_hetzner_floating_ip(floating_id, server_id)
        elif account["provider"] == "vultr":
            res = await provider.attach_vultr_reserved_ip(floating_id, server_id)
        elif account["provider"] == "upcloud":
            _confirm(args, "ASSIGN_FLOATING_IP")
            res = await provider.attach_upcloud_floating_ip(floating_id, server_id)
        elif account["provider"] == "cloudferro":
            res = await provider.attach_cloudferro_floating_ip(
                floating_id, server_id, port_id=args.get("port_id"))
        else:
            raise InputError(f"Floating IP assignment not supported on {account['provider']}")
        _delete_cache(store, "all_floating_ips")
        _delete_cache(store, "all_servers")
        _record_activity(store, "ASSIGN_FLOATING_IP", provider=account.get("provider", ""),
                              target=str(floating_id), status="success", details=f"Assigned to server {server_id}")
        return {"assigned": True, "floating_id": floating_id, "server_id": server_id, "result": res}

    if operation == "unassign_floating_ip":
        floating_id = _required(args, "floating_id")
        if account["provider"] == "hetzner":
            res = await provider.unassign_hetzner_floating_ip(floating_id)
        elif account["provider"] == "vultr":
            res = await provider.detach_vultr_reserved_ip(floating_id)
        elif account["provider"] == "upcloud":
            _confirm(args, "UNASSIGN_FLOATING_IP")
            res = await provider.detach_upcloud_floating_ip(floating_id)
        elif account["provider"] == "cloudferro":
            res = await provider.detach_cloudferro_floating_ip(floating_id)
        else:
            raise InputError(f"Floating IP unassignment not supported on {account['provider']}")
        _delete_cache(store, "all_floating_ips")
        _delete_cache(store, "all_servers")
        _record_activity(store, "UNASSIGN_FLOATING_IP", provider=account.get("provider", ""),
                              target=str(floating_id), status="success", details=f"Detached floating IP {floating_id}")
        return {"unassigned": True, "floating_id": floating_id, "result": res}

    if operation == "update_floating_ip":
        floating_id = _required(args, "floating_id")
        ip = args.get("ip")
        ptr = args.get("ptr")
        if account["provider"] == "hetzner" and ip and ptr:
            res = await provider.change_hetzner_floating_ip_ptr(floating_id, ip, ptr)
            _delete_cache(store, "all_floating_ips")
            return {"updated": True, "result": res}
        if account["provider"] == "upcloud":
            _confirm(args, "UPDATE_FLOATING_IP")
            release_policy = args.get("release_policy")
            if ptr is None and release_policy is None:
                raise InputError("ptr or release_policy is required for UpCloud")
            res = await provider.update_upcloud_ip(floating_id, ptr=ptr,
                                                   release_policy=release_policy)
            _delete_cache(store, "all_floating_ips")
            _delete_cache(store, "all_servers")
            return {"updated": True, "floating_id": floating_id, "result": res}
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
        upcloud_networking = None
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
        elif account.get("provider") == "upcloud":
            try:
                upcloud_networking = await provider.upcloud_networking(server_id)
            except Exception:
                pass
        return {
            "server": srv_pub,
            "floating_ips": attached_fips,
            "primary_ips": primary_ips,
            "linode_networking": linode_networking,
            "upcloud_networking": upcloud_networking,
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
        _record_activity(store, "SWAP_IPS", provider="linode",
                              target=f"{server_id} <-> {target_server_id}", status="success",
                              details="Swapped IPv4 addresses between linodes")
        return {"swapped": True, "server_id": server_id, "target_server_id": target_server_id, "result": res}

    if operation == "delete_server":
        _confirm(args, "DELETE_SERVER")
        await provider.delete_server(server_id)
        store.delete_server_pass(account_id, server_id)
        _delete_cache(store, "all_servers")
        _delete_cache(store, "all_floating_ips")
        _record_activity(store, "DELETE_SERVER", provider=account.get("provider", ""),
                              target=str(server_id), status="success", details=f"Server {server_id} destroyed")
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
        elif account["provider"] == "upcloud":
            if action not in {"start", "halt", "shutdown", "reboot"}:
                raise InputError("action must be start, halt, shutdown, or reboot")
            _confirm(args, action.upper())
            await provider.power_server(server_id, action)
        elif account["provider"] == "cloudferro":
            if action not in {"start", "halt", "shutdown", "stop", "reboot"}:
                raise InputError("action must be start, stop, or reboot")
            _confirm(args, action.upper())
            await provider.power_server(server_id, action)
        else:
            raise InputError(f"power_server not supported for {account['provider']}")
        _delete_cache(store, "all_servers")
        _record_activity(store, "POWER_ACTION", provider=account.get("provider", ""),
                              target=str(server_id), status="success", details=f"Power {action} on server {server_id}")
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
            elif account["provider"] == "upcloud":
                zone = args.get("zone") or server.get("region")
                if not zone:
                    raise InputError("zone is required for UpCloud floating IP allocation")
                policy = _required(args, "release_policy").lower()
                result = await provider.create_upcloud_floating_ip(server_id, zone, policy)
            elif account["provider"] == "cloudferro":
                result = await provider.create_cloudferro_floating_ip(server_id)
            else:
                raise InputError("floating IPs are supported for Vultr and Hetzner")
        else:
            # Standalone creation without attached server
            region = args.get("region") or ("waw3-1" if account["provider"] == "cloudferro" else None)
            if not region and account["provider"] in {"vultr", "hetzner"}:
                raise InputError("region is required for standalone floating IP allocation")
            ip_type = args.get("ip_type", "ipv4")
            label = args.get("name", "floating-ip")
            if account["provider"] == "vultr":
                result = await provider.create_vultr_reserved_ip(region, ip_type="v4" if ip_type in ("v4", "ipv4") else "v6", label=label)
            elif account["provider"] == "hetzner":
                result = await provider.create_hetzner_floating_ip(server_id=None, ip_type=ip_type, name=label, home_location=region)
            elif account["provider"] == "linode":
                raise InputError("Linode does not support ephemeral floating IPs. Use Linode IP Swap or IP Sharing via Akamai Cloud Manager.")
            elif account["provider"] == "upcloud":
                raise InputError("UpCloud allocation requires server_id and cannot be standalone")
            elif account["provider"] == "cloudferro":
                result = await provider.create_cloudferro_floating_ip()
            else:
                raise InputError("floating IPs are supported for Vultr and Hetzner")
        _delete_cache(store, "all_floating_ips")
        _delete_cache(store, "all_servers")
        _record_activity(store, "CREATE_FLOATING_IP", provider=account.get("provider", ""),
                              target=str(result.get("ip") or result.get("address") or "new-ip"), status="success",
                              details=f"Allocated floating IP for server {server_id or 'standalone'}")
        return {"floating_ip": result, "configure_guest_os": account["provider"] == "hetzner"}

    if operation == "delete_floating_ip":
        _confirm(args, "DELETE_FLOATING_IP")
        floating_id = _required(args, "floating_id")
        if server_id and server_id != "0":
            attached = await _floating(provider, server_id)
            if not any(str(row.get("id") or row.get("address")) == floating_id
                       for row in attached):
                raise InputError("floating IP is not attached to the specified server")
        if account["provider"] == "vultr":
            await provider.delete_vultr_floating_ip(floating_id)
        elif account["provider"] == "hetzner":
            await provider.delete_hetzner_floating_ip(floating_id)
        elif account["provider"] == "upcloud":
            # UpCloud identifies an IP by its address rather than a numeric ID.
            await provider.delete_upcloud_ip(floating_id)
        elif account["provider"] == "cloudferro":
            await provider.delete_cloudferro_floating_ip(floating_id)
        else:
            raise InputError("floating IPs are supported for Vultr and Hetzner")
        _delete_cache(store, "all_floating_ips")
        _delete_cache(store, "all_servers")
        _record_activity(store, "DELETE_FLOATING_IP", provider=account.get("provider", ""),
                              target=str(floating_id), status="success", details="Floating IP deleted")
        return {"deleted": True, "floating_id": floating_id}

    raise InputError("unknown operation")


def _dns_public(record):
    if not record:
        return None
    return {key: record.get(key) for key in ("id", "name", "content", "ttl", "proxied", "type")}
