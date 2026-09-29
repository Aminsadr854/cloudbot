# Cloudbot API and MCP guide

Cloudbot offers owner automation through a loopback JSON API and an MCP stdio server. Both use the same operations and the existing encrypted Cloudbot database. The phone probe API on port 9600 is separate.

## Install

`sudo ./install.sh` installs the API and MCP dependency, preserves or creates `/opt/cloudbot/data/control_api.token` (mode `0600`), and starts `cloudbot-control-api.service`. The API binds to **127.0.0.1:9601**. It is never published by the installer.

For an existing installation, copy the current project `.py` files and `requirements.txt` into `/opt/cloudbot`, then install requirements and the service:

```sh
sudo /opt/cloudbot/venv/bin/pip install -r /opt/cloudbot/requirements.txt
sudo sh -c 'test -s /opt/cloudbot/data/control_api.token || /opt/cloudbot/venv/bin/python -c "import secrets; print(secrets.token_urlsafe(48))" > /opt/cloudbot/data/control_api.token'
sudo chmod 600 /opt/cloudbot/data/control_api.token
sudo tee /etc/systemd/system/cloudbot-control-api.service >/dev/null <<'UNIT'
[Unit]
Description=Cloudbot owner automation API (loopback only)
After=network-online.target
[Service]
Type=simple
WorkingDirectory=/opt/cloudbot
EnvironmentFile=/opt/cloudbot/cloudbot.env
ExecStart=/opt/cloudbot/venv/bin/python /opt/cloudbot/control_api.py
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
UNIT
sudo systemctl daemon-reload
sudo systemctl enable --now cloudbot-control-api
```

Check the listener with `curl http://127.0.0.1:9601/health`; it returns `{"status":"ok"}`. For errors use `journalctl -u cloudbot-control-api -n 50 --no-pager`. A healthy listener does not establish that every cloud provider is reachable.

## API requests

Every `/v1/` request requires `Authorization: Bearer <contents of control_api.token>`. Do not put the token in a URL, AI prompt, or checked-in config. A local example:

```sh
TOKEN=$(sudo cat /opt/cloudbot/data/control_api.token)
curl -sS -H "Authorization: Bearer $TOKEN" http://127.0.0.1:9601/v1/operations
curl -sS -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{}' http://127.0.0.1:9601/v1/operations/accounts
curl -sS -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"account_id":1}' http://127.0.0.1:9601/v1/operations/servers
unset TOKEN
```

Use `GET /v1/operations` to discover operation names. All operations use `POST /v1/operations/{name}` with a JSON object body. Invalid input returns HTTP 400, invalid auth returns 401, and an internal/provider failure returns 502 with details in the service log. JSON requests are limited to 16 KiB.

For access from your workstation, open an SSH tunnel with `ssh -L 9601:127.0.0.1:9601 root@YOUR_CLOUDBOT_HOST`, then call `http://127.0.0.1:9601` locally. Supply the token through a protected local secret store. Keep the API on loopback even if you use a tunnel.

| Operation | JSON arguments | Effect |
|---|---|---|
| `accounts` | `{}` | Account IDs, labels, and providers; no tokens or proxy secrets |
| `account_info` | `account_id` | Provider identity, balance, and credit details |
| `servers` | `account_id` | Servers in the account |
| `server` | `account_id`, `server_id` | One server and attached Floating IPs |
| `regions` | `account_id` | Available locations |
| `plans` | `account_id`, `region` | Available plans and price labels |
| `images` | `account_id` | OS images |
| `floating_ips` | `account_id`, `server_id` | Attached Reserved/Floating IPs |
| `watch_status` | `{}` | Watchdog settings and latest results |
| `tunnels` | `{}` | Registered tunnel IDs and endpoints without encrypted details |
| `dns_zones` | `{}` | Cloudflare zones |
| `dns_record` | `name` | A record or `null` |
| `create_server` | `account_id`, `name`, `region`, `plan`, `image`, `confirm: "CREATE_SERVER"` | Creates one billable server; root password is encrypted and stored |
| `power_server` | `account_id`, `server_id`, `action`, `confirm` | Vultr start, halt, reboot; confirmation is `START`, `HALT`, `REBOOT` |
| `create_floating_ip` | `account_id`, `server_id`, `ip_type`, `confirm: "CREATE_FLOATING_IP"` | Billable Vultr IPv4 or Hetzner IPv4/IPv6 |
| `delete_floating_ip` | `account_id`, `server_id`, `floating_id`, `confirm: "DELETE_FLOATING_IP"` | Permanently deletes an attached IP |
| `upsert_dns` | `name`, `ip`, `confirm: "UPSERT_DNS"` | Creates or repoints a Cloudflare A record |

Example creation body after calling `regions`, `plans`, and `images`:

```json
{"account_id":1,"name":"node-01","region":"fsn1","plan":"cx23","image":"ubuntu-24.04","confirm":"CREATE_SERVER"}
```

Server root passwords are never returned by the API or MCP. The owner can retrieve one from its SSH details in Telegram. Hetzner Floating IP allocation does not configure the guest OS. Server deletion, panel node provisioning, provider credential management, and tunnel repair remain Telegram workflows.

## MCP connection

The MCP server uses the [official Python MCP SDK](https://github.com/modelcontextprotocol/python-sdk) v2 and stdio. Launch it on the Cloudbot host through SSH: it reads the local token file and calls the local API. It opens no MCP network port. A command-based MCP client configuration is:

```json
{
  "mcpServers": {
    "cloudbot": {
      "command": "ssh",
      "args": ["-T", "root@YOUR_CLOUDBOT_HOST", "/opt/cloudbot/venv/bin/python", "/opt/cloudbot/mcp_server.py"]
    }
  }
}
```

Set up SSH key access first. The remote account needs permission to read `/opt/cloudbot/data/control_api.token`. Make sure SSH login scripts do not print banners to stdout, which would corrupt stdio MCP. Restart the AI client's MCP connection after changing server code.

MCP tools are `list_accounts`, `account_info`, `list_servers`, `get_server`, `list_regions`, `list_plans`, `list_images`, `list_floating_ips`, `watchdog_status`, `list_tunnels`, `list_dns_zones`, `get_dns_record`, `create_server`, `power_server`, `create_floating_ip`, `delete_floating_ip`, and `upsert_dns`. Their typed parameters mirror the API arguments. Start with `list_accounts` to find account IDs, then use read tools to inspect current resources and choices.

For write tools, the AI should obtain the owner's approval for the specific action and target before supplying the confirmation string. The string is an input guard, not a substitute for approval. A timeout does not establish that a paid action failed; inspect the resource list before retrying.

The API bearer token authorizes **all listed operations**, including billable ones. Treat SSH access and the token as owner credentials. Do not publicly reverse proxy the API without adding a separate access layer. The phone probe token cannot authorize it.
