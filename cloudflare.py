"""
Cloudflare DNS, just the two operations the bot needs: create an A record for a
new subdomain, and repoint an existing subdomain at a new IP.

No proxy here - unlike the cloud providers, Cloudflare's API has no per-account
geo restriction, so the request goes out directly.

Records are created grey-clouded (proxied=false) on purpose. These subdomains
point at VPN relays and nodes; a proxied record would hide the real IP behind
Cloudflare and break the tunnel. On an update the existing proxied flag is kept
as-is, so a record someone deliberately set to proxied stays that way.
"""
import aiohttp

BASE = "https://api.cloudflare.com/client/v4"


class CFError(Exception):
    pass


class Cloudflare:
    def __init__(self, token: str):
        self.token = token

    async def _req(self, method, path, **kw):
        headers = {"Authorization": f"Bearer {self.token}",
                   "Content-Type": "application/json"}
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as s:
            async with s.request(method, BASE + path, headers=headers, **kw) as r:
                data = await r.json(content_type=None)
                if not data.get("success", False):
                    errs = "; ".join(e.get("message", "") for e in data.get("errors", []))
                    raise CFError(errs or f"HTTP {r.status}")
                return data["result"]

    async def zones(self):
        """[(zone_id, name)] across all pages the token can see."""
        out, page = [], 1
        while True:
            res = await self._req("GET", f"/zones?per_page=50&page={page}")
            out += [(z["id"], z["name"]) for z in res]
            if len(res) < 50:
                break
            page += 1
        return out

    async def zone_for(self, fqdn: str):
        """Find the zone a fully-qualified name belongs to (longest suffix match)."""
        zones = await self.zones()
        match = [(zid, name) for zid, name in zones
                 if fqdn == name or fqdn.endswith("." + name)]
        if not match:
            return None
        return max(match, key=lambda z: len(z[1]))

    async def find_a_record(self, zone_id, fqdn):
        res = await self._req(
            "GET", f"/zones/{zone_id}/dns_records?type=A&name={fqdn}")
        return res[0] if res else None

    async def create_a(self, zone_id, fqdn, ip, proxied=False, ttl=60):
        return await self._req(
            "POST", f"/zones/{zone_id}/dns_records",
            json={"type": "A", "name": fqdn, "content": ip,
                  "ttl": ttl, "proxied": proxied})

    async def update_a(self, zone_id, record, ip):
        # Preserve the record's existing proxied flag and ttl.
        return await self._req(
            "PUT", f"/zones/{zone_id}/dns_records/{record['id']}",
            json={"type": "A", "name": record["name"], "content": ip,
                  "ttl": record.get("ttl", 60),
                  "proxied": record.get("proxied", False)})

    async def delete_record(self, zone_id, record_id):
        return await self._req("DELETE", f"/zones/{zone_id}/dns_records/{record_id}")

