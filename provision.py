"""
Turn a freshly created server into a Pasarguard node.

This runs when the owner presses "node it". Deliberately it does NOT use the
account's proxy: the proxy exists so the bot can talk to a cloud provider's API
from the right country, but the node install is an SSH session straight to the
server, and the panel then reaches the node directly - a proxy in the middle
would only get in the way.

The steps, in order and each checked before the next:
  1. wait for SSH to come up (a new server needs a minute to boot)
  2. ufw disable, so the firewall cannot block the node's ports
  3. install pg-node with defaults, non-interactively
  4. read back the node's self-signed certificate and its api key
  5. register the node in the panel on the SNI-SCAN core

The certificate matters: the panel is the client and the node the server, so
the panel has to be told the node's cert (server_ca) to trust it. Skipping that
is the usual reason a freshly installed node shows up "unhealthy".
"""
import asyncio
import ssl

import asyncssh

PG_NODE_URL = "https://github.com/PasarGuard/scripts/raw/main/pg-node.sh"
CERT_PATH = "/var/lib/pasarguard-node/certs/ssl_cert.pem"
ENV_PATH = "/opt/pasarguard-node/.env"
SERVICE_PORT = 62050
API_PORT = 62051


async def _connect(host, password, user="root", port=22, timeout=25):
    return await asyncio.wait_for(
        asyncssh.connect(host, port=port, username=user, password=password,
                         known_hosts=None), timeout=timeout)


async def wait_for_ssh(host, password, attempts=20, delay=15, log=None,
                       user="root", port=22):
    """A new server is not reachable the instant the API returns; poll for it."""
    last = ""
    for i in range(attempts):
        try:
            conn = await _connect(host, password, user=user, port=port, timeout=20)
            conn.close()
            return True
        except Exception as e:
            last = f"{type(e).__name__}"
            if log:
                await log(f"  … waiting for SSH ({i + 1}/{attempts}): {last}")
            await asyncio.sleep(delay)
    raise RuntimeError(f"SSH never came up ({last})")


async def _run(conn, cmd, timeout=600):
    r = await asyncio.wait_for(conn.run(cmd, check=False), timeout=timeout)
    return r.exit_status, (r.stdout or "") + (r.stderr or "")


async def provision_node(host, password, log, user="root", port=22):
    """
    Install pg-node on `host` and return (server_ca, api_key). `log` is an async
    callable used to stream progress back to the chat.
    """
    await log("در حال اتصال به سرور (SSH)…")
    await wait_for_ssh(host, password, log=log, user=user, port=port)

    async with await _connect(host, password, user=user, port=port, timeout=30) as conn:
        await log("غیرفعال‌کردن فایروال (ufw disable)…")
        await _run(conn, "ufw --force disable 2>/dev/null; ufw disable 2>/dev/null; true")

        # A freshly booted cloud server runs apt itself (cloud-init /
        # unattended-upgrades), so the installer's own apt-get collides with it
        # and fails to install Docker. Wait for those to finish and for the
        # locks to clear before installing.
        await log("در انتظار آماده‌شدن سرور (قفل apt)…")
        # Stopping the updaters only after the lock clears was not enough: the
        # apt-daily timers start them again moments later, mid-install, and a
        # Docker install interrupted that way leaves dpkg half-configured so
        # every later attempt fails too. Stop the timers first, then wait, then
        # finish whatever dpkg left undone before installing anything.
        wait_apt = (
            "systemctl stop apt-daily.timer apt-daily-upgrade.timer "
            "unattended-upgrades 2>/dev/null || true; "
            "cloud-init status --wait >/dev/null 2>&1 || true; "
            "for i in $(seq 1 90); do "
            "  fuser /var/lib/dpkg/lock-frontend /var/lib/apt/lists/lock "
            "/var/lib/dpkg/lock >/dev/null 2>&1 || break; sleep 5; "
            "done; "
            "systemctl stop apt-daily.service apt-daily-upgrade.service "
            "unattended-upgrades 2>/dev/null || true; "
            "export DEBIAN_FRONTEND=noninteractive; "
            "dpkg --configure -a >/dev/null 2>&1 || true; "
            "apt-get -y -f install >/dev/null 2>&1 || true"
        )
        await _run(conn, wait_apt, timeout=900)

        await log("نصب نود پاسارگارد (چند دقیقه طول می‌کشد)…")
        # -y and the INSTALL_* env vars keep the installer from stopping on a
        # prompt; without them the script blocks forever waiting on a TTY.
        install = (
            "export DEBIAN_FRONTEND=noninteractive; "
            "export INSTALL_SERVICE_PORT=62050; "
            'yes "" | sudo -E bash -c "$(curl -sL %s)" @ install -y '
            "> /root/pgnode-install.log 2>&1; "
            "tail -n 3 /root/pgnode-install.log" % PG_NODE_URL
        )
        code, out = await _run(conn, install, timeout=900)
        await log(f"خروجی نصب:\n<code>{out.strip()[-400:]}</code>")

        # One retry after repairing dpkg: the usual failure on a new box is a
        # package step that collided with the OS's own first-boot updates, and a
        # second pass on a settled system succeeds.
        _, probe_cert = await _run(
            conn, f"test -s {CERT_PATH} && echo ok || "
                  "find /var/lib -name ssl_cert.pem 2>/dev/null | head -1")
        if not probe_cert.strip():
            await log("نصب کامل نشد؛ ترمیم dpkg و تلاش دوباره…")
            await _run(conn, wait_apt, timeout=900)
            code, out = await _run(conn, install, timeout=900)
            await log(f"خروجی نصب دوم:\n<code>{out.strip()[-400:]}</code>")

        await log("خواندن گواهی و کلید نود…")
        _, cert = await _run(conn, f"cat {CERT_PATH} 2>/dev/null")
        # The install may land under a couple of paths across versions; find it.
        if "BEGIN CERTIFICATE" not in cert:
            _, cert = await _run(
                conn, "find /var/lib -name ssl_cert.pem 2>/dev/null "
                      "| head -1 | xargs cat 2>/dev/null")
        _, keyout = await _run(
            conn, r"grep -hoP 'API_KEY\s*=\s*\K\S+' "
                  "/opt/*/.env /opt/pasarguard-node/.env 2>/dev/null | head -1")
        api_key = keyout.strip()

        if "BEGIN CERTIFICATE" not in cert:
            raise RuntimeError("could not read the node certificate after install")
        if not api_key:
            raise RuntimeError("could not read the node api key after install")
        return cert.strip(), api_key


class Panel:
    """
    Pasarguard panel client: add a node, list nodes, delete a node.

    Routes (prefix /api/node): POST /api/node to add, GET /api/nodes to list
    ({"nodes": [...]}), DELETE /api/node/{id} to remove. A node counts as
    "down" when its status is anything other than "connected".
    """

    def __init__(self, base_url, username, password):
        self.base = base_url.rstrip("/")
        self.username = username
        self.password = password
        self._ctx = ssl.create_default_context()
        self._ctx.check_hostname = False
        self._ctx.verify_mode = ssl.CERT_NONE

    def _session(self):
        import aiohttp
        return aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=60))

    async def _token(self, session):
        async with session.post(
            f"{self.base}/api/admin/token",
            data={"username": self.username, "password": self.password,
                  "grant_type": "password"}, ssl=self._ctx) as r:
            d = await r.json()
            return d["access_token"]

    async def _list(self, session, tok):
        async with session.get(f"{self.base}/api/nodes",
                               headers={"Authorization": f"Bearer {tok}"},
                               ssl=self._ctx) as r:
            d = await r.json()
        return d if isinstance(d, list) else (d.get("nodes") or d.get("items") or [])

    async def _delete(self, session, tok, node_id):
        async with session.delete(f"{self.base}/api/node/{node_id}",
                                  headers={"Authorization": f"Bearer {tok}"},
                                  ssl=self._ctx) as r:
            return r.status in (200, 204)

    async def hosts(self):
        """Every host entry the panel serves to clients."""
        async with self._session() as s:
            tok = await self._token(s)
            async with s.get(f"{self.base}/api/hosts",
                             headers={"Authorization": f"Bearer {tok}"},
                             ssl=self._ctx) as r:
                d = await r.json()
        if isinstance(d, list):
            return d
        if isinstance(d, dict):
            out = []
            for v in d.values():
                out.extend(v if isinstance(v, list) else [v])
            return out
        return []

    async def list_nodes(self):
        async with self._session() as s:
            tok = await self._token(s)
            return await self._list(s, tok)

    async def delete_nodes_by_address(self, address, name=None):
        """
        Remove panel nodes that match a deleted server. Matched on address (the
        node's address is the server IP, which is unique); name is a fallback.
        Returns the list of removed (id, name).
        """
        removed = []
        async with self._session() as s:
            tok = await self._token(s)
            for n in await self._list(s, tok):
                if n.get("address") == address or (name and n.get("name") == name):
                    if await self._delete(s, tok, n["id"]):
                        removed.append((n["id"], n.get("name")))
        return removed

    async def add_node(self, name, address, server_ca, api_key,
                       core_config_id, port=SERVICE_PORT, api_port=API_PORT):
        body = {
            "name": name, "address": address,
            "port": port, "api_port": api_port,
            "connection_type": "grpc", "usage_coefficient": 1.0,
            "keep_alive": 60, "core_config_id": core_config_id,
            "server_ca": server_ca, "api_key": api_key,
        }

        async def _post(s, tok):
            async with s.post(f"{self.base}/api/node", json=body,
                              headers={"Authorization": f"Bearer {tok}"},
                              ssl=self._ctx) as r:
                return r.status, await r.text()

        import json
        async with self._session() as s:
            tok = await self._token(s)
            status, text = await _post(s, tok)
            if status < 400:
                return json.loads(text)

            # A duplicate name or address is the common failure when re-noding a
            # server. If the clashing node is down, it is the stale one from the
            # previous attempt - remove it and try once more. A *connected* node
            # with the same name is a real conflict and is left alone.
            low = text.lower()
            if "exist" in low or "duplicate" in low or "already" in low or status == 409:
                stale = None
                for n in await self._list(s, tok):
                    if n.get("name") == name or n.get("address") == address:
                        if n.get("status") != "connected":
                            stale = n
                            break
                if stale:
                    await self._delete(s, tok, stale["id"])
                    status2, text2 = await _post(s, tok)
                    if status2 < 400:
                        return json.loads(text2)
                    raise RuntimeError(f"panel add-node failed after removing "
                                       f"stale node: {status2}:{text2[:150]}")
                raise RuntimeError(f"a node named '{name}' (or at {address}) "
                                   f"already exists and is connected; not replacing it")
            raise RuntimeError(f"panel add-node failed: {status}:{text[:200]}")
