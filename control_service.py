"""Owner automation operations shared by the HTTP API and MCP bridge.

Never return decrypted account credentials, proxy passwords, or server passwords.
Cloud resources can cost money, so mutations require an exact confirmation value.
"""

import ipaddress
import re
import secrets

from cloudflare import Cloudflare
from providers import Provider


class InputError(ValueError):
    pass


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
}


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


def _account_public(account):
    return {key: account.get(key) for key in
            ("id", "label", "provider", "proxy_family", "auto_backup", "created_at")}


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


async def execute(operation, args, store):
    """Execute one documented operation with validated, JSON-safe arguments."""
    if operation not in OPERATIONS:
        raise InputError("unknown operation")
    if not isinstance(args, dict):
        raise InputError("args must be a JSON object")

    if operation == "accounts":
        return {"accounts": [_account_public(a) for a in store.accounts()]}
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

    if operation in {"dns_zones", "dns_record", "upsert_dns"}:
        token = store.cf_token()
        if not token:
            raise InputError("Cloudflare token is not configured")
        cf = Cloudflare(token)
        if operation == "dns_zones":
            return {"zones": [{"id": zid, "name": name} for zid, name in await cf.zones()]}
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
        return {"regions": [{"id": key, "label": label} for key, label in
                            await provider.regions(force=True)]}
    if operation == "plans":
        region = _required(args, "region")
        return {"region": region, "plans": [{"id": key, "label": label} for key, label in
                                            await provider.plans(region, force=True)]}
    if operation == "images":
        return {"images": [{"id": key, "label": label} for key, label in
                           await provider.images()]}

    if operation == "create_server":
        _confirm(args, "CREATE_SERVER")
        name = _required(args, "name")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", name):
            raise InputError("name must use letters, digits, _ or - and be at most 64 characters")
        region, plan, image = (_required(args, field) for field in ("region", "plan", "image"))
        if account["provider"] == "hetzner":
            available = {key for key, _ in await provider.plans(region, force=True)}
            if plan not in available:
                raise InputError("Hetzner plan is unavailable in this region; list plans again")
        password = secrets.token_urlsafe(24)
        server = await provider.create_server(name, region, plan, image, password,
                                              auto_backup=account.get("auto_backup"))
        store.set_server_pass(account_id, server["id"], server.get("root_password") or password)
        return {"server": _server_public(server), "password_stored": True}

    server_id = _required(args, "server_id")
    if operation == "server":
        return {"server": _server_public(await provider.server(server_id)),
                "floating_ips": await _floating(provider, server_id)}
    if operation == "floating_ips":
        return {"floating_ips": await _floating(provider, server_id)}
    if operation == "power_server":
        if account["provider"] != "vultr":
            raise InputError("power_server currently supports Vultr only")
        action = _required(args, "action")
        if action not in {"start", "halt", "reboot"}:
            raise InputError("action must be start, halt, or reboot")
        _confirm(args, action.upper())
        await provider.vultr_power(server_id, action)
        return {"accepted": True, "action": action, "server_id": server_id}
    if operation == "create_floating_ip":
        _confirm(args, "CREATE_FLOATING_IP")
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
        else:
            raise InputError("floating IPs are supported for Vultr and Hetzner")
        return {"floating_ip": result, "configure_guest_os": account["provider"] == "hetzner"}
    if operation == "delete_floating_ip":
        _confirm(args, "DELETE_FLOATING_IP")
        floating_id = _required(args, "floating_id")
        attached = await _floating(provider, server_id)
        if not any(str(row.get("id")) == floating_id for row in attached):
            raise InputError("floating IP is not attached to the specified server")
        if account["provider"] == "vultr":
            await provider.delete_vultr_floating_ip(floating_id)
        elif account["provider"] == "hetzner":
            await provider.delete_hetzner_floating_ip(floating_id)
        else:
            raise InputError("floating IPs are supported for Vultr and Hetzner")
        return {"deleted": True, "floating_id": floating_id}
    raise InputError("unknown operation")


def _dns_public(record):
    if not record:
        return None
    return {key: record.get(key) for key in ("id", "name", "content", "ttl", "proxied")}
