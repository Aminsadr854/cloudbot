# cloudbot

A Telegram bot that runs the unglamorous half of a VPN operation: cloud
accounts, tunnels, DNS, and a watchdog that notices a config is dead before the
customers do — and usually fixes it.

Most settings are configured from inside Telegram. The installer asks for the
bot token, owner id, and initial panel settings; it also creates a separate
root-only token for the local owner automation API.

## What it does

**Cloud accounts.** Linode, Vultr, Hetzner, UpCloud, and CloudFerro, each reached through its own
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
UpCloud uses zones, plans, and zone-compatible storage templates in the same
wizard. It accepts selected public keys from the local SSH vault at creation;
UpCloud has no account-level SSH-key sync. A generated fallback password is not
saved unless UpCloud itself returns a one-time password.

**Panel nodes.** Provision a new server and attach it to a Pasarguard/Marzban
panel in one step: firewall down, node installed, certificate and API key read
back, node registered. Duplicate names are cleaned up rather than stacked.

**Tunnels.** GRE and paytun between an Iran relay and a foreign box, with port
forwarding, teardown, and registration of tunnels you built by hand so the
watchdog can repair them too.

**Owner webhook.** `POST /v1/webhook/notify` on the control API forwards a message from an external script to the owner's Telegram, behind its own token (see `AI_API_MCP.md`). The Gemini exit watchdog in `projects/gemini-watchdog` uses it. A message may carry inline `buttons`, restricted to `td:<verb>:<ref>` callbacks so the notify token cannot forge the bot's own menu callbacks; `tdoctor_ui.py` handles those taps and replies to tunnel-doctor messages by forwarding them to the doctor's control API (see `projects/tunnel-doctor/README.md`, "Telegram").

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

Open **🌐 ارائه‌دهندگان پراکسی (Proxy providers)** to save a provider and
its supplied identities. NiceProxy/SwiftProxy use username session IDs;
DataImpulse uses sticky ports instead. Import full DataImpulse lines or use
`http://LOGIN__cr.{country}:PASSWORD@gw.dataimpulse.com:{port}` with ports such
as `10000-10014`. Country codes become lowercase; the port stays the supplied
identity when changing country. HTTP is the default; SOCKS formats need a
`socks5://` prefix. Numeric session IDs retain leading zeros and duration
settings remain part of the format. `{session_id}` is an alias for `{session}`.

New providers default to a **0.1 GB** Cloudbot traffic allowance (decimal GB).
Provider cards show usage and limit; Edit or the Telegram provider menu can
change the limit or reset usage. **0 means unlimited**. Existing providers keep
unlimited allowances during migration. Counters persist across restarts and
are shared by bot and API processes. Exhaustion blocks live provider requests
and new allocations; it does not trigger proxy replacement. Cloud API calls,
Keystone authentication, retries and standalone proxy tests count HTTP headers
and application body bytes. This is not vendor billing: TLS/CONNECT overhead,
socket buffering and traffic outside Cloudbot are excluded. Read allowance is
reserved before reading; interrupted reads may conservatively retain it.

Add accounts from **➕ Add account** using a provider/country, a manual proxy,
or direct access. Existing routes are under **Manage account → Proxy**.
Country changes retain an available identity; **🔄 سشن دیگر** selects another
supplied identity. Add providers from the picker without restarting account
import. Disabled providers/IDs keep their existing bindings but cannot receive
new assignments. Delete or edit formats only while unused. Availability is
counted per country; manual edits and concurrent allocation cannot duplicate
one provider/country/identity pair. Replacing a route or deleting an account
releases its binding. Connection tests reserve candidates for ten minutes;
failures and cancellation release them, and stale replies cannot overwrite
newer account changes.

A cloud API allowlist sees the proxy's outbound address; a country/session identity does
not guarantee a permanently fixed or distinct public IP from the provider.

The control API syncs inventory, balances/access, and IPs at startup and hourly.
Cloudbot changes automatically queue another sync, even without a browser:
account edits persist in SQLite; API mutations and Telegram server changes
queue affected accounts. The worker checks every 2s, serializes passes, and
preserves changes arriving mid-sync. Deleted accounts trigger inventory pruning.
Visible consoles check `sync_status` every 3s and reload completed snapshots;
provider reads retain saved inventory on failure. Refresh fetches the selected
account/provider or all accounts in global views. Navigation and server cards
stay local; IP search uses the saved index. Requests allow 120s (connect 45s/read
90s), proxy tests 90s. Confirmation and provisioning checks stay live.

**Accounts → Check all accounts** validates API access, billing where supported,
and inventory. Server `suspended`/`billing_suspension` marks the account **Suspended**
in Telegram, API checks, and console cards; balances remain visible. Successful
refreshes clear suspension after recovery. Stopped servers and debt alone do not
imply suspension; Telegram flags other API/billing problems with `!`.

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

**UpCloud** uses its own bearer API token, encrypted with other cloud account
credentials. The web console and Telegram bot list servers, deploy from a
public storage template in the selected zone, start, stop, reboot, and delete
servers, and inject selected public SSH keys from the local vault during
creation. Floating IPv4 allocation attaches to a server and asks for an
explicit `keep` or `release` policy. The server must be stopped before
allocating or changing floating/interface addresses. The UpCloud network panel
lists interfaces and supports eligible secondary IP add/remove operations while
stopped. These API operations do not configure the guest operating system;
configure the guest network separately when adding an address or interface.
Account checks verify UpCloud API access; Cloudbot does not show balance figures
that its account API does not provide.

## Requirements

* Debian or Ubuntu with systemd, Python 3.10+
* A box inside Iran you can reach over SSH — the watchdog and the scanner are
  worthless measured from anywhere else
* `paytun` in `assets/` if you want tunnels (see the paytun project)

## Web Hosting Console & API for automation

The web console and owner API listen on `127.0.0.1:9601`:
* **Web Hosting Dashboard (`http://127.0.0.1:9601`)**: A responsive single-page console providing full hosting capabilities:
  - Multi-cloud server inventory (Hetzner, Vultr, Linode, UpCloud) with live power controls, root password reveals from the encrypted vault, and instance teardown.
  - Interactive deployment wizard with dynamic region/plan inventory and SSH key injection.
  - Floating IP & Reserved IP management: allocation, attachment to instances, reverse DNS PTR records, and copyable guest OS network configuration commands. UpCloud address actions use server-aware controls and explicit release policy.
  - SSH Key Vault: in-browser Ed25519 keypair generation and public key storage; UpCloud uses selected local vault keys during deployment because it has no account-level SSH-key API.
  - Accounts opens with connected provider logos and account/server counts; choose a provider to list its accounts, then use All providers to return. Edit account changes the display name or verifies and replaces the API token; leaving the token empty preserves it. More → Add/Edit note edits a plain memo with password autofill suppressed. Proxy pool routing and Cloudflare DNS are also managed here.
  - The dashboard loads the last known local snapshot; Refresh requests a live sync. A status strip shows whether data is syncing, current, stale, or needs attention; failed resource loads retain their last known values and expose a retry action.
  - Read requests retry bounded network and transient server failures. Account errors distinguish invalid/expired API tokens, API access restrictions, provider errors, and explicit proxy failures. Only explicit proxy failures offer proxy reconfiguration or automatic session replacement; the console rechecks the route before replacement and verifies the account afterward. Action dialogs explain the effect and offer Yes/No without typing. Destructive actions never retry automatically.
  - Local access via loopback or SSH tunnel: `ssh -L 9601:127.0.0.1:9601 root@YOUR_CLOUDBOT_HOST`.
* **Automation API & MCP**: JSON operations protected by bearer token for AI clients (Claude, Cursor, Antigravity) and custom tooling. See [AI_API_MCP.md](AI_API_MCP.md) for endpoints, confirmation guardrails, and MCP setup.

## Notes

* Only the owner id can use the bot. Every message and button from anyone else
  is refused.
* Panel credentials, relay logins and the subscription link are encrypted like
  the cloud credentials and proxy formats. Measurements are not — they are
  operational data, and being able to read them is worth more than hiding them.
* Automatic server replacement is off until you switch it on. It spends money.

**CloudFerro** uses the OpenStack API in the WAW3-1 region. Add it as a
`cloudferro` account and use an encrypted JSON token containing the application
credential and project id, for example
`{"id":"...","secret":"...","project_id":"..."}`. The bot authenticates
against Keystone and supports account checks, server inventory, region/flavor/
image discovery, create/delete, and start/stop/reboot. CloudFerro billing and
floating-IP management are not exposed by this integration.
