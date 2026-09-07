# Cloudbot overview

Cloudbot is an owner-only Telegram control bot for VPN infrastructure. It is a
long-running Python service that uses Telegram polling, rather than a public
webhook.

## Capabilities

- Stores and manages Linode, Vultr, and Hetzner accounts, including optional
  per-account HTTP or SOCKS proxies with default, IPv4-only, or IPv6-only
  proxy-host connection behavior; lists, creates, and deletes cloud servers.
- Provisions a newly created server as a Pasarguard/Marzban panel node.
- Builds and tracks GRE or paytun links and their port forwards.
- Creates and changes Cloudflare DNS records, and can scan Cloudflare ranges
  from an Iran relay to identify a stable endpoint.
- Imports subscription targets and probes them from Iran; it distinguishes
  ordinary outages from likely filtering, alerts only after repeated failures,
  and can perform guarded repair workflows when explicitly enabled.

## Security and operation

Only the configured Telegram owner may use it. The service keeps provider
tokens, proxies, panel credentials, relay credentials, Cloudflare token, and
subscription URL encrypted in its SQLite store; the encryption key is a
separate root-only file. It is installed under `/opt/cloudbot` and managed as
the `cloudbot` systemd unit. On a new installation, use `/start` and
**Settings** in Telegram to configure the panel, Iran relay, and Cloudflare;
add provider accounts separately.

Automatic server replacement is disabled by default because it can incur cloud
charges.
