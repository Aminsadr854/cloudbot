"""Cloudbot MCP tools over stdio. Run on the Cloudbot host through SSH."""

import os

import aiohttp
from mcp.server import MCPServer

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
                raise ValueError(result.get("error", f"HTTP {response.status}"))
            return result


@mcp.tool()
async def list_accounts() -> dict:
    """List cloud accounts and their IDs. Credentials and proxy secrets are omitted."""
    return await _call("accounts")


@mcp.tool()
async def account_info(account_id: int) -> dict:
    """Check a cloud account's access and balance/credit details."""
    return await _call("account_info", account_id=account_id)


@mcp.tool()
async def list_servers(account_id: int) -> dict:
    """List servers for one account, including regions, plans, IPs, and status."""
    return await _call("servers", account_id=account_id)


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
async def list_floating_ips(account_id: int, server_id: str) -> dict:
    """List Vultr Reserved IPs or Hetzner Floating IPs attached to a server."""
    return await _call("floating_ips", account_id=account_id, server_id=server_id)


@mcp.tool()
async def watchdog_status() -> dict:
    """Read watchdog settings, targets, and the latest health results."""
    return await _call("watch_status")


@mcp.tool()
async def list_tunnels() -> dict:
    """List registered tunnel IDs and endpoints without tunnel credentials."""
    return await _call("tunnels")


@mcp.tool()
async def list_dns_zones() -> dict:
    """List Cloudflare DNS zones available to Cloudbot."""
    return await _call("dns_zones")


@mcp.tool()
async def get_dns_record(name: str) -> dict:
    """Read a Cloudflare A record by its full DNS name."""
    return await _call("dns_record", name=name)


@mcp.tool()
async def create_server(account_id: int, name: str, region: str, plan: str,
                        image: str, confirm: str) -> dict:
    """Create one billable server. First list regions, plans, and images. Ask the owner before calling; confirm must be CREATE_SERVER. The root password stays encrypted in Cloudbot."""
    return await _call("create_server", account_id=account_id, name=name,
                       region=region, plan=plan, image=image, confirm=confirm)


@mcp.tool()
async def power_server(account_id: int, server_id: str, action: str, confirm: str) -> dict:
    """Start, halt, or reboot a Vultr server. Ask the owner first; confirm must equal START, HALT, or REBOOT."""
    return await _call("power_server", account_id=account_id, server_id=server_id,
                       action=action, confirm=confirm)


@mcp.tool()
async def create_floating_ip(account_id: int, server_id: str, ip_type: str,
                             confirm: str) -> dict:
    """Create a billable Vultr IPv4 or Hetzner IPv4/IPv6 Floating IP. Ask the owner first; confirm must be CREATE_FLOATING_IP. Hetzner guest OS configuration is separate."""
    return await _call("create_floating_ip", account_id=account_id,
                       server_id=server_id, ip_type=ip_type, confirm=confirm)


@mcp.tool()
async def delete_floating_ip(account_id: int, server_id: str, floating_id: str,
                             confirm: str) -> dict:
    """Permanently delete an attached Floating IP. Ask the owner first; confirm must be DELETE_FLOATING_IP."""
    return await _call("delete_floating_ip", account_id=account_id,
                       server_id=server_id, floating_id=floating_id, confirm=confirm)


@mcp.tool()
async def upsert_dns(name: str, ip: str, confirm: str) -> dict:
    """Create or repoint a Cloudflare A record. Ask the owner first; confirm must be UPSERT_DNS. Existing proxy and TTL settings are preserved."""
    return await _call("upsert_dns", name=name, ip=ip, confirm=confirm)


if __name__ == "__main__":
    mcp.run(transport="stdio")
