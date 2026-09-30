# cloudbot

A Telegram bot that runs the unglamorous half of a VPN operation: cloud
accounts, tunnels, DNS, and a watchdog that notices a config is dead before the
customers do — and usually fixes it.

Most settings are configured from inside Telegram. The installer asks for the
bot token, owner id, and initial panel settings; it also creates a separate
root-only token for the local owner automation API.

## What it does

**Cloud accounts.** Linode, Vultr and Hetzner, each reached through its own
proxy (`host:port:user:pass`, HTTP or SOCKS). List, create and delete servers.
API tokens and proxies are encrypted at rest with a key in its own root-only
file, so the database on its own is inert.

The server-creation wizard accepts up to 10 names, one per line, and creates
them sequentially with a separate password for each.
Hetzner locations and plans are filtered by the API's per-location availability
and refreshed before provisioning, so unsupported or unavailable plan/location
combinations are not offered. A last-second capacity change is reported with a
button to reload the choices. Root passwords are encrypted in the bot database
and appear only when you open that server's SSH details.

**Panel nodes.** Provision a new server and attach it to a Pasarguard/Marzban
panel in one step: firewall down, node installed, certificate and API key read
back, node registered. Duplicate names are cleaned up rather than stacked.

**Tunnels.** GRE and paytun between an Iran relay and a foreign box, with port
forwarding, teardown, and registration of tunnels you built by hand so the
watchdog can repair them too.

**Cloudflare DNS.** Create a subdomain, repoint one at a new IP, with the
proxied flag left as you set it.

**Clean-IP scanner.** Narrows Cloudflare's announced ranges from *inside Iran*
in stages — reachable, then a real TLS handshake with an interception check,
then repeated probes for loss and jitter, then a download on the finalists.
Ranking punishes loss and jitter far above latency, because a steady 90 ms path
beats a 40 ms one that stalls. Optionally repoints a domain at the winner.

**Config watchdog.** Imports your configs from a subscription link, re-reads it
daily, and probes each one from inside Iran. It separates *filtered* from *down*
— TCP connecting while TLS is reset is filtering, not an outage — and only acts
after a failure survives repeated confirmation, because a relay that drops one
probe has not broken.

When something is genuinely down it repairs it:

* a direct config gets a replacement server on the same account, region and
  plan. Candidate IPs are tested from Iran *before* anything is installed on
  them, so a blocked address is discarded in seconds rather than after a
  three-minute node build.
* a tunnelled config gets its tunnel rebuilt — same transport first, then the
  other one, then a new foreign endpoint.
* the account itself is checked before either, because several tunnels usually
  share one, and a suspension takes them all down together.

Nothing is torn down until its replacement answers from Iran, failed attempts
are destroyed immediately so they cannot quietly bill, and there is a daily cap
per config so a filtered datacenter cannot turn into an unbounded server bill.
If every account of a provider is gone it asks you what to do — wait for a new
account, or take a temporary home elsewhere and move back automatically when
one appears.

## Install

```
git clone git@github.com:Aminsadr854/cloudbot.git && cd cloudbot
sudo ./install.sh
```

It asks for a bot token and your numeric Telegram id, installs to
`/opt/cloudbot`, and starts a systemd service.

Then open the bot, send `/start`, and fill in **⚙️ Settings**:

| setting | what it is |
| --- | --- |
| 🎛 Panel | your panel URL, admin user and password, and the core id new nodes attach to (`0` lets the panel decide). Tested before it is saved. |
| 🇮🇷 Iran relay | `host:port:user:password` of a box inside Iran. Everything that has to be measured from Iran runs there. |
| 🌐 Cloudflare token | an API token that can edit DNS in your zones. |

Cloud provider accounts are added from **➕ Add account**, each with its own
proxy if it needs one. After entering a proxy, choose whether Cloudbot reaches
that proxy using its default DNS behavior, IPv4 only, or IPv6 only. The latter
two resolve the proxy hostname to the requested family before provider calls.
Each account appears on one row. Open it and choose **⚙️ Manage account** to
rename it or manage its proxy, including editing individual fields. The family
choice affects Cloudbot's connection to the proxy; the proxy's own outbound
address is what a provider API access allowlist sees.

Cloudbot warms local account, server, Floating IP, and Hetzner Primary IP
snapshots at startup. Account/server menus, primary IP pages, and location
choices reuse them immediately; stale data refreshes in the background. A
minute-based refresh detects changes made outside the bot, and refresh buttons
fetch current data on demand. Bot mutations invalidate the affected account
and refresh it; old in-flight responses cannot repopulate an invalidated cache.
Provider checks for confirmations and IP changes remain live. Sending an IP
opens its locally indexed server card; cache misses return immediately.

The **🖥 Accounts → 🔍 Check all accounts** button checks every API key and
connection. It reads balances for Linode and Vultr, validates Hetzner project
access, and marks accounts with API failures or an outstanding balance with `!`
in the account list until the next check or bot restart.

All bot messages and keyboard labels use the owner-created [Infrastructure Icons](https://t.me/addemoji/datacenter_emojis_by_vpnmanagerkiabot)
custom-emoji pack. The pack contains thirteen static 100×100 PNG custom emojis:
ten infrastructure/status icons plus the actual Linode, Vultr, and Hetzner
provider marks. The bot converts normal Unicode emoji globally and keeps the
same character as the fallback for clients that cannot render custom emoji.
Carbon source SVGs are licensed under Apache-2.0; provider source URLs and
licenses are recorded in `assets/emoji/datacenter/source/PROVIDER-LOGOS.txt`.
The reproducible renderers are `assets/emoji/datacenter/build_stickers.py` and
`assets/emoji/datacenter/build_provider_logos.py`.

For Vultr instances, the server screen can add a public IPv4 (Vultr reboots the
instance) or create and attach a Reserved IPv4 floating IP. Vultr does not
replace an existing primary IPv4 in place; the additional-address action keeps
the original primary address. The Vultr IP manager lists the floating IPs
attached to that instance and can create or permanently remove them; it also
offers confirmed start, stop, and reboot controls. Its cached view opens
immediately when available; provider lookups acknowledge the tap and show
progress, while failures remain visible with retry and back buttons.

For Hetzner accounts and servers, **🌐 Primary IPها** opens the paginated
project-wide IPv4/IPv6 inventory, including unassigned allocations. Create
1–20 IPs at a time by choosing location, family, and count; rename them, toggle
delete protection or deletion with the server, assign/replace, unassign, or
delete free IPs. Purchases and changes require an expiring single-use
confirmation. Servers have confirmed shutdown/start buttons; assignment and
unassignment require the server to be off and assignment requires the same
location. Replacement retains the old IP with auto-delete disabled and attempts
to restore it if assignment fails. Free IPs still incur charges. Bulk creation
stops on the first failure and reports the allocations already created. After
changing IPs, start the server and update dependent SSH, DNS, panel, and tunnel
settings as needed. IPv6 may need guest network configuration.

**🌐 Manage IPs** on Hetzner servers lists attached Floating IPs and can
create or permanently remove IPv4 and IPv6 Floating IPs. IPv6 Floating IPs are
allocated as a `/64` network; Hetzner bills Floating IPs monthly. The API
assignment does not configure the guest OS. The manager and server card show a
copyable command for temporarily adding each address; it is lost at reboot.
Configure the OS network for persistence, and remove the guest address
separately when deleting the IP.

## Requirements

* Debian or Ubuntu with systemd, Python 3.10+
* A box inside Iran you can reach over SSH — the watchdog and the scanner are
  worthless measured from anywhere else
* `paytun` in `assets/` if you want tunnels (see the paytun project)

## API and MCP for AI clients

The owner automation API listens on `127.0.0.1:9601` with its own bearer token.
An MCP stdio server exposes named tools through SSH and calls that API. They can
inspect accounts, servers, watchdog status, tunnels, and DNS, as well as create
servers, manage Floating IPs, control Vultr power, and update DNS with explicit
confirmation values. See [AI_API_MCP.md](AI_API_MCP.md) for installation,
authentication, the full operation table, examples, and MCP client setup.

## Notes

* Only the owner id can use the bot. Every message and button from anyone else
  is refused.
* Provider tokens, proxies, panel credentials, relay logins and the subscription
  link are encrypted. Host names, ports and measurements are not — they are
  operational data, and being able to read them is worth more than hiding them.
* Automatic server replacement is off until you switch it on. It spends money.
