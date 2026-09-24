# cloudbot

A Telegram bot that runs the unglamorous half of a VPN operation: cloud
accounts, tunnels, DNS, and a watchdog that notices a config is dead before the
customers do — and usually fixes it.

Everything is configured from inside Telegram. The installer asks for a bot
token and an owner id; nothing else is ever written to a file or a unit.

## What it does

**Cloud accounts.** Linode, Vultr and Hetzner, each reached through its own
proxy (`host:port:user:pass`, HTTP or SOCKS). List, create and delete servers.
API tokens and proxies are encrypted at rest with a key in its own root-only
file, so the database on its own is inert.

The server-creation wizard accepts up to 10 names, one per line, and creates
them sequentially with a separate password for each.

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
git clone <this repo> cloudbot && cd cloudbot
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
Each account also has an inline **⚙️ Settings** screen for viewing its provider,
proxy endpoint and family preference, and for renaming or changing/removing its
proxy.

For Vultr instances, the server screen can add a public IPv4 (Vultr reboots the
instance) or create and attach a Reserved IPv4 floating IP. Vultr does not
replace an existing primary IPv4 in place; the additional-address action keeps
the original primary address. The Vultr IP manager lists the floating IPs
attached to that instance and can create or permanently remove them; it also
offers confirmed start, stop, and reboot controls.

## Requirements

* Debian or Ubuntu with systemd, Python 3.10+
* A box inside Iran you can reach over SSH — the watchdog and the scanner are
  worthless measured from anywhere else
* `paytun` in `assets/` if you want tunnels (see the paytun project)

## Notes

* Only the owner id can use the bot. Every message and button from anyone else
  is refused.
* Provider tokens, proxies, panel credentials, relay logins and the subscription
  link are encrypted. Host names, ports and measurements are not — they are
  operational data, and being able to read them is worth more than hiding them.
* Automatic server replacement is off until you switch it on. It spends money.
