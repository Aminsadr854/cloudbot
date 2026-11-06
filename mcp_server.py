"""Cloudbot MCP tools over stdio. Run on the Cloudbot host through SSH."""

import os

import aiohttp
from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from control_api import read_token

mcp = MCPServer("Cloudbot")


async def _call(operation: str, **args) -> dict:
    base = os.environ.get("CLOUDBOT_CONTROL_URL", "http://127.0.0.1:9601").rstrip("/")
    timeout = aiohttp.ClientTimeout(total=120)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.post(
            f"{base}/v1/operations/{operation}", json=args,
            headers={"Authorization": f"Bearer {read_token()}"},
        ) as response:
            result = await response.json()
            if response.status != 200:
                raise ToolError(result.get("error", f"HTTP {response.status}"))
            return result


# ---- Account & System Introspection -----------------------------------------

@mcp.tool()
async def list_accounts() -> dict:
    """List cloud accounts and their IDs. Credentials and proxy secrets are omitted."""
    return await _call("accounts")


@mcp.tool()
async def account_info(account_id: int) -> dict:
    """Check a cloud account's access and balance/credit details."""
    return await _call("account_info", account_id=account_id)


@mcp.tool()
async def resource_limits(account_id: int) -> dict:
    """Read provider resource limits, quotas, and current usage for an account."""
    return await _call("resource_limits", account_id=account_id)


@mcp.tool()
async def check_all_accounts(refresh: bool = False) -> dict:
    """Check credentials and balance across all accounts. Cached unless refresh is true."""
    return await _call("check_all_accounts", refresh=refresh)


@mcp.tool()
async def test_account(account_id: int) -> dict:
    """Live-test one account's connectivity, proxy route, and billing."""
    return await _call("test_account", account_id=account_id)


# ---- Server Inventory & Lifecycle -------------------------------------------

@mcp.tool()
async def list_servers(account_id: int) -> dict:
    """List servers for one account, including regions, plans, IPs, and status."""
    return await _call("servers", account_id=account_id)


@mcp.tool()
async def all_servers(refresh: bool = False) -> dict:
    """List servers across every account. Uses the cache unless refresh is true, which polls the clouds."""
    return await _call("all_servers", refresh=refresh)


@mcp.tool()
async def get_server(account_id: int, server_id: str) -> dict:
    """Get a server and its attached floating IPs. Root passwords are omitted."""
    return await _call("server", account_id=account_id, server_id=server_id)


@mcp.tool()
async def list_regions(account_id: int) -> dict:
    """List current locations where this account may create servers."""
    return await _call("regions", account_id=account_id)


@mcp.tool()
async def list_plans(account_id: int, region: str) -> dict:
    """List current plans and prices for a selected region."""
    return await _call("plans", account_id=account_id, region=region)


@mcp.tool()
async def list_images(account_id: int) -> dict:
    """List available operating-system images for server creation."""
    return await _call("images", account_id=account_id)


@mcp.tool()
async def create_server(
    account_id: int,
    name: str,
    region: str,
    plan: str,
    image: str,
    confirm: str,
    ssh_key_ids: list[int] | None = None,
    ssh_keys: list[str] | None = None,
    use_vault_keys: bool = True,
    enable_ipv6: bool = False,
    count: int = 1,
) -> dict:
    """Create one or more billable servers. First list regions, plans, and images. Ask the owner before calling; confirm must be CREATE_SERVER. The root password stays encrypted in Cloudbot.

    Args:
        account_id: Target cloud account ID.
        name: Server name / hostname label.
        region: Datacenter region code.
        plan: Server plan / flavor ID.
        image: OS image ID or slug.
        confirm: Must be 'CREATE_SERVER'.
        ssh_key_ids: Optional list of Cloudbot vault SSH key IDs (e.g. [1]).
        ssh_keys: Optional list of SSH key names or public key strings (e.g. ['main'] or ['ssh-ed25519 ...']).
        use_vault_keys: If True (default), automatically attaches saved vault SSH keys when no explicit keys given.
        enable_ipv6: Enable IPv6 if supported by provider (default False).
        count: Number of instances to deploy in batch (1-20, default 1).
    """
    args = {
        "account_id": account_id,
        "name": name,
        "region": region,
        "plan": plan,
        "image": image,
        "confirm": confirm,
        "use_vault_keys": use_vault_keys,
        "enable_ipv6": enable_ipv6,
        "count": count,
    }
    if ssh_key_ids is not None:
        args["ssh_key_ids"] = ssh_key_ids
    if ssh_keys is not None:
        args["ssh_keys"] = ssh_keys
    return await _call("create_server", **args)


@mcp.tool()
async def delete_server(account_id: int, server_id: str, confirm: str) -> dict:
    """Permanently terminate and delete a cloud server. Ask the owner first; confirm must be DELETE_SERVER."""
    return await _call("delete_server", account_id=account_id, server_id=server_id, confirm=confirm)


@mcp.tool()
async def power_server(account_id: int, server_id: str, action: str, confirm: str) -> dict:
    """Start, halt, stop, shutdown, or reboot a server. Ask the owner first; confirm must equal the uppercase action (e.g. START, HALT, REBOOT, SHUTDOWN)."""
    return await _call("power_server", account_id=account_id, server_id=server_id,
                       action=action, confirm=confirm)


@mcp.tool()
async def server_password(account_id: int, server_id: str, confirm: str) -> dict:
    """Reveal the decrypted root password for a server. Ask the owner first; confirm must be SHOW_PASSWORD."""
    return await _call("server_password", account_id=account_id, server_id=server_id, confirm=confirm)


@mcp.tool()
async def set_server_password(account_id: int, server_id: str, password: str) -> dict:
    """Save or update the stored root password for a server in the encrypted vault."""
    return await _call("set_server_password", account_id=account_id, server_id=server_id, password=password)


# ---- SSH Key Vault ----------------------------------------------------------

@mcp.tool()
async def list_ssh_keys() -> dict:
    """List public SSH keys stored in the Cloudbot vault."""
    return await _call("ssh_keys")


@mcp.tool()
async def add_ssh_key(name: str, public_key: str, sync_accounts: bool = True) -> dict:
    """Add a new public SSH key to the Cloudbot vault and optionally sync to cloud accounts."""
    return await _call("add_ssh_key", name=name, public_key=public_key, sync_accounts=sync_accounts)


@mcp.tool()
async def delete_ssh_key(key_id: int, confirm: str) -> dict:
    """Delete an SSH key from the Cloudbot vault. Ask the owner first; confirm must be DELETE_SSH_KEY."""
    return await _call("delete_ssh_key", key_id=key_id, confirm=confirm)


# ---- Floating & Reserved IPs ------------------------------------------------

@mcp.tool()
async def list_floating_ips(account_id: int, server_id: str) -> dict:
    """List Vultr Reserved IPs or Hetzner Floating IPs attached to a server."""
    return await _call("floating_ips", account_id=account_id, server_id=server_id)


@mcp.tool()
async def all_floating_ips(account_id: int | None = None, refresh: bool = False) -> dict:
    """List Floating/Reserved IPs across accounts (or one account). Cached unless refresh is true."""
    args = {"refresh": refresh}
    if account_id is not None:
        args["account_id"] = account_id
    return await _call("all_floating_ips", **args)


@mcp.tool()
async def create_floating_ip(account_id: int, ip_type: str, confirm: str,
                             server_id: str = "", home_location: str = "") -> dict:
    """Create a billable Floating/Reserved IP. Ask the owner first; confirm must be CREATE_FLOATING_IP. Provide server_id to attach, or home_location for standalone Hetzner floating IP."""
    args = {"account_id": account_id, "ip_type": ip_type, "confirm": confirm}
    if server_id:
        args["server_id"] = server_id
    if home_location:
        args["home_location"] = home_location
    return await _call("create_floating_ip", **args)


@mcp.tool()
async def delete_floating_ip(account_id: int, floating_id: str, confirm: str,
                             server_id: str = "") -> dict:
    """Permanently delete an attached Floating IP. Ask the owner first; confirm must be DELETE_FLOATING_IP."""
    args = {"account_id": account_id, "floating_id": floating_id, "confirm": confirm}
    if server_id:
        args["server_id"] = server_id
    return await _call("delete_floating_ip", **args)


@mcp.tool()
async def assign_floating_ip(account_id: int, floating_id: str, server_id: str) -> dict:
    """Assign/attach an existing floating or reserved IP to a server."""
    return await _call("assign_floating_ip", account_id=account_id,
                       floating_id=floating_id, server_id=server_id)


@mcp.tool()
async def unassign_floating_ip(account_id: int, floating_id: str,
                               confirm: str = "UNASSIGN_FLOATING_IP") -> dict:
    """Unassign/detach a floating IP from its server. UpCloud requires confirm='UNASSIGN_FLOATING_IP'."""
    return await _call("unassign_floating_ip", account_id=account_id,
                       floating_id=floating_id, confirm=confirm)


@mcp.tool()
async def update_floating_ip(account_id: int, floating_id: str, ip: str = "",
                             ptr: str = "", release_policy: str = "",
                             confirm: str = "UPDATE_FLOATING_IP") -> dict:
    """Update floating IP reverse DNS PTR or label/release policy."""
    args = {"account_id": account_id, "floating_id": floating_id, "confirm": confirm}
    if ip:
        args["ip"] = ip
    if ptr:
        args["ptr"] = ptr
        args["dns_ptr"] = ptr
    if release_policy:
        args["release_policy"] = release_policy
    return await _call("update_floating_ip", **args)


# ---- Hetzner Primary IPs ----------------------------------------------------

@mcp.tool()
async def hetzner_primary_ips(account_id: int, refresh: bool = False) -> dict:
    """List Hetzner Primary IPs for an account. Cached unless refresh is true."""
    return await _call("hetzner_primary_ips", account_id=account_id, refresh=refresh)


@mcp.tool()
async def create_hetzner_primary_ip(account_id: int, location: str, ip_type: str,
                                    name: str, confirm: str) -> dict:
    """Allocate a Hetzner Primary IP. Ask the owner first; confirm must be CREATE_PRIMARY_IP."""
    return await _call("create_hetzner_primary_ip", account_id=account_id,
                       location=location, ip_type=ip_type, name=name, confirm=confirm)


@mcp.tool()
async def assign_hetzner_primary_ip(account_id: int, ip_id: str, server_id: str) -> dict:
    """Assign a Hetzner Primary IP to a server."""
    return await _call("assign_hetzner_primary_ip", account_id=account_id,
                       ip_id=ip_id, server_id=server_id)


@mcp.tool()
async def unassign_hetzner_primary_ip(account_id: int, ip_id: str) -> dict:
    """Unassign a Hetzner Primary IP from a server."""
    return await _call("unassign_hetzner_primary_ip", account_id=account_id, ip_id=ip_id)


@mcp.tool()
async def delete_hetzner_primary_ip(account_id: int, ip_id: str, confirm: str) -> dict:
    """Permanently delete a Hetzner Primary IP. Ask the owner first; confirm must be DELETE_PRIMARY_IP."""
    return await _call("delete_hetzner_primary_ip", account_id=account_id,
                       ip_id=ip_id, confirm=confirm)


# ---- Cloudflare DNS ---------------------------------------------------------

@mcp.tool()
async def list_dns_zones() -> dict:
    """List Cloudflare DNS zones available to Cloudbot."""
    return await _call("dns_zones")


@mcp.tool()
async def list_dns_records(zone_id: str = "", zone_name: str = "") -> dict:
    """List Cloudflare DNS records in a zone, selected by zone_id or zone_name."""
    return await _call("dns_records", **{k: v for k, v in
                                         {"zone_id": zone_id, "zone_name": zone_name}.items() if v})


@mcp.tool()
async def get_dns_record(name: str) -> dict:
    """Read a Cloudflare A record by its full DNS name."""
    return await _call("dns_record", name=name)


@mcp.tool()
async def upsert_dns(name: str, ip: str, confirm: str) -> dict:
    """Create or repoint a Cloudflare A record. Ask the owner first; confirm must be UPSERT_DNS. Existing proxy and TTL settings are preserved."""
    return await _call("upsert_dns", name=name, ip=ip, confirm=confirm)


@mcp.tool()
async def delete_dns_record(zone_id: str, record_id: str, confirm: str) -> dict:
    """Delete a Cloudflare DNS record. Ask the owner first; confirm must be DELETE_DNS."""
    return await _call("delete_dns_record", zone_id=zone_id, record_id=record_id, confirm=confirm)


# ---- Account & Proxy Management ---------------------------------------------

@mcp.tool()
async def add_account(label: str, provider: str, token: str, region: str = "",
                      proxy: str = "", proxy_provider_id: str = "",
                      proxy_family: str = "default", auto_backup: str = "disabled",
                      note: str = "") -> dict:
    """Add a cloud account (provider: linode, vultr, hetzner, upcloud, cloudferro). region is a country code like ES. Give proxy_provider_id (an id from proxy_pool, or "auto") to bind a pool proxy for that region, or a raw proxy string; note is an optional memo; token is stored encrypted."""
    args = {"label": label, "provider": provider, "token": token,
            "proxy_family": proxy_family, "auto_backup": auto_backup}
    for key, value in (("region", region), ("proxy", proxy), ("proxy_provider_id", proxy_provider_id), ("note", note)):
        if value:
            args[key] = value
    return await _call("add_account", **args)


@mcp.tool()
async def set_account_note(account_id: int, note: str) -> dict:
    """Set or update an account's note/memo."""
    return await _call("set_account_note", account_id=account_id, note=note)


@mcp.tool()
async def delete_account(account_id: int, confirm: str) -> dict:
    """Remove a cloud account from Cloudbot (does not touch servers at the provider). Ask the owner first; confirm must be DELETE_ACCOUNT."""
    return await _call("delete_account", account_id=account_id, confirm=confirm)


@mcp.tool()
async def set_account_region(account_id: int, region: str) -> dict:
    """Set an account's country/region code, e.g. ES."""
    return await _call("set_account_region", account_id=account_id, region=region)


@mcp.tool()
async def set_account_proxy(account_id: int, proxy: str = "", proxy_family: str = "default",
                            region: str = "") -> dict:
    """Set an account's raw proxy (host:port:user:pass or URL). An empty proxy clears it."""
    args = {"account_id": account_id, "proxy": proxy, "proxy_family": proxy_family}
    if region:
        args["region"] = region
    return await _call("set_account_proxy", **args)


@mcp.tool()
async def allocate_account_proxy(account_id: int, provider_id: int, country: str = "",
                                 another: bool = False) -> dict:
    """Bind a free session from a rotating proxy provider pool to an account. country defaults to the account's region; another=true takes a different session."""
    args = {"account_id": account_id, "provider_id": provider_id, "another": another}
    if country:
        args["country"] = country
    return await _call("allocate_account_proxy", **args)


@mcp.tool()
async def test_proxy(proxy: str = "", account_id: int = 0) -> dict:
    """Test a raw proxy string, or an account's configured proxy, and return its exit IP and latency."""
    args = {}
    if proxy:
        args["proxy"] = proxy
    if account_id:
        args["account_id"] = account_id
    return await _call("test_proxy", **args)


@mcp.tool()
async def proxy_providers() -> dict:
    """List proxy providers with session counts and the accounts bound to each."""
    return await _call("proxy_providers")


@mcp.tool()
async def proxy_sessions(provider_id: int) -> dict:
    """List a proxy provider's sessions with allocation and binding status."""
    return await _call("proxy_sessions", provider_id=provider_id)


@mcp.tool()
async def proxy_availability(country: str, provider_id: str = "auto") -> dict:
    """Count unallocated sessions for a country on one provider, or on all enabled providers with "auto"."""
    return await _call("proxy_availability", country=country, provider_id=provider_id)


@mcp.tool()
async def add_proxy_provider(label: str, template: str, session_ids: str = "",
                             scheme: str = "http", family: str = "default",
                             usage_limit_gb: float = 0) -> dict:
    """Add a rotating proxy provider. template is host:port:user:pass or a URL, with {port}/{country}/{session} placeholders as the provider requires; session_ids is a list, a range like 10000-10010, or bulk proxy lines."""
    args = {"label": label, "template": template, "session_ids": session_ids,
            "scheme": scheme, "family": family}
    if usage_limit_gb:
        args["usage_limit_gb"] = usage_limit_gb
    return await _call("add_proxy_provider", **args)


@mcp.tool()
async def update_proxy_provider(provider_id: int, label: str = "", template: str = "",
                                scheme: str = "http", default: bool = False,
                                usage_limit_gb: float = -1, reset_usage: bool = False) -> dict:
    """Rename a proxy provider, change its template, make it the default, set its usage limit in GB (0 = unlimited), or reset its usage counter."""
    args = {"provider_id": provider_id, "scheme": scheme}
    if label:
        args["label"] = label
    if template:
        args["template"] = template
    if default:
        args["default"] = True
    if usage_limit_gb >= 0:
        args["usage_limit_gb"] = usage_limit_gb
    if reset_usage:
        args["reset_usage"] = True
    return await _call("update_proxy_provider", **args)


@mcp.tool()
async def delete_proxy_provider(provider_id: int, confirm: str) -> dict:
    """Delete a proxy provider and its sessions. Ask the owner first; confirm must be DELETE_PROXY_PROVIDER."""
    return await _call("delete_proxy_provider", provider_id=provider_id, confirm=confirm)


@mcp.tool()
async def toggle_proxy_provider(provider_id: int) -> dict:
    """Enable or disable a proxy provider."""
    return await _call("toggle_proxy_provider", provider_id=provider_id)


@mcp.tool()
async def add_proxy_sessions(provider_id: int, session_ids: str) -> dict:
    """Add sessions to a provider from IDs, a range like 10000-10010, or pasted proxy lines."""
    return await _call("add_proxy_sessions", provider_id=provider_id, session_ids=session_ids)


@mcp.tool()
async def toggle_proxy_session(provider_id: int, session_id: str) -> dict:
    """Enable or disable one session in a provider pool."""
    return await _call("toggle_proxy_session", provider_id=provider_id, session_id=session_id)


@mcp.tool()
async def delete_proxy_session(provider_id: int, session_id: str) -> dict:
    """Remove one session from a provider pool."""
    return await _call("delete_proxy_session", provider_id=provider_id, session_id=session_id)


@mcp.tool()
async def auto_heal_proxies(account_id: int = 0) -> dict:
    """Replace broken proxies with working pool sessions, for one account or all accounts."""
    return await _call("auto_heal_proxies", **({"account_id": account_id} if account_id else {}))


# ---- Proxies, Tunnels, & Watchdog -------------------------------------------

@mcp.tool()
async def proxy_pool() -> dict:
    """List proxy pools, provider sessions, and account bindings. Secrets are masked."""
    return await _call("proxy_pool")


@mcp.tool()
async def watchdog_status() -> dict:
    """Read watchdog settings, targets, and the latest health results."""
    return await _call("watch_status")


@mcp.tool()
async def list_tunnels() -> dict:
    """List registered tunnel IDs and endpoints without tunnel credentials."""
    return await _call("tunnels")


if __name__ == "__main__":
    transport = os.environ.get("CLOUDBOT_MCP_TRANSPORT", "stdio")
    if transport == "stdio":
        mcp.run(transport="stdio")
    else:
        from mcp.server.transport_security import TransportSecuritySettings
        hosts = [h for h in os.environ.get("CLOUDBOT_MCP_ALLOWED_HOSTS", "").split(",") if h]
        security = TransportSecuritySettings(
            enable_dns_rebinding_protection=bool(hosts),
            allowed_hosts=hosts, allowed_origins=[],
        )
        mcp.run(
            transport=transport,
            host=os.environ.get("CLOUDBOT_MCP_HOST", "127.0.0.1"),
            port=int(os.environ.get("CLOUDBOT_MCP_PORT", "9602")),
            stateless_http=True, json_response=True, transport_security=security,
        )
