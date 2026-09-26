# Egern configuration

This repository migrates the current behavior of
[`frostmage1250/mihomo-script`](https://github.com/frostmage1250/mihomo-script)
to an Egern profile.

- [`Profile.yaml`](https://raw.githubusercontent.com/frostmage1250/egern-config/main/Profile.yaml)
  is the Egern profile.
- Egern-native rule sets, including APNs, are generated in
  [`frostmage1250/proxy-rules-converter`](https://github.com/frostmage1250/proxy-rules-converter/tree/main/dist/egern).
  This profile references their stable `main/dist/egern/*.yaml` URLs.
- `reports/source.json` records the pinned converter manifest and commit, the
  verified rule sources, policy counts, and the generated profile hash.
- GitHub Actions refreshes the generated repository files every six hours and can also
  be run manually. The Egern profile itself deliberately has no root
  `auto_update`; re-import it manually when you want to replace the active profile.

## Subscription setup

Subscription credentials are deliberately not committed to this public repository.
After importing `Profile.yaml` into Egern, add the private subscription URL
to the **订阅** policy group. The profile sets `default_subscription_group` to **订阅** and
`default_proxy_group` to **代理**. The private URL remains in Egern instead of this public
repository. Region groups flatten and filter **订阅**,
so future node changes continue to flow into 台湾、新加坡、日本、美国、其他节点
and 低倍率节点 automatically. Telegram and 媒体 also expose 订阅 as an
additional selectable policy. Because a full profile replacement overwrites
locally added subscription URLs, profile updates are manual; remote rule sets and
the locally configured node subscription can still update independently.

## Migration behavior

The generator reads the Mihomo script commit recorded in the published rule
manifest on every run and preserves its rule
order, policies, region filters, service groups, DNS choices, and Hosts mappings.
This includes the dedicated GitHub and Claude groups, Claude-before-AI routing,
and the consolidated Meta domain/IP pair without redundant Facebook or Threads
providers. Every paired business IP rule must immediately follow its domain rule
and is emitted with Egern's native `no_resolve: true`; the build fails if a future
Mihomo update breaks that invariant.
Two user-requested Egern overrides precede the Mihomo routing rules: a global
`protocol: stun` rule routed to `REJECT`, followed by the APNs override.
The APNs classical domain/IPv4/IPv6 entries are converted in the rule converter into `dist/egern/apns.yaml`,
routed through `Proxy`, and remain first in DNS Forward with `Foreign`.
Mihomo `default-nameserver` endpoints are converted to the same IP addresses in
Egern `bootstrap` (plain UDP is required by Egern). Mihomo `nameserver-policy`
and every explicit Direct domain rule become ordered Egern DNS Forward rules that
use `system`; the foreign DNS group remains the final catch-all. Mihomo
`nameserver` policy suffixes are preserved semantically: Egern receives clean
DNS server URLs plus explicit, high-priority routing rules that bind each DNS
server endpoint to the same policy (for example, `#Proxy` becomes
`policy: Proxy`). Missing, conflicting, or unsupported policy mappings fail the
build instead of being silently discarded. The generated `real_ip_domains`
list mirrors [Repcz's Egern profile](https://github.com/Repcz/Tool/blob/X/Egern/Egern.yaml);
other Fake-IP behavior follows Egern defaults. DNS hijacking targets port 53.
The existing DNS Hosts mappings are preserved, with AliDNS IPv4 addresses
added. MESL private DNS is used only as Egern `proxy_nameservers`, while
normal DNS forwarding stays separate. Egern cannot reproduce Mihomo's runtime
`direct-nameserver` re-resolution when a selectable policy group is switched to
Direct, so the generator preserves every statically identifiable Direct domain
rule and records that platform boundary in `reports/source.json`.

The only deliberate platform mapping is that Mihomo's IPv4/IPv6-preferred DIRECT
pseudo-proxies become Egern's built-in `DIRECT`; Egern has no equivalent
per-DIRECT-policy IP-version selector.

## Generation boundary

`proxy-rules-converter` publishes and verifies all Egern-native rules and the
`reports/egern-source.json` manifest first. This repository pins that published
converter commit, uses the manifest's Mihomo commit to render `Profile.yaml`,
and verifies every referenced YAML against its manifest hash. The workflow
commits only `Profile.yaml` and `reports/source.json`; it no longer generates
`rules/*.yaml`. Existing rule files remain as read-only compatibility paths
for profiles imported before the migration.
