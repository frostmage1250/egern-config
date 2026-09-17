# Egern configuration

This repository migrates the current behavior of
[`frostmage1250/mihomo-script`](https://github.com/frostmage1250/mihomo-script)
to an Egern profile.

- [`Profile.yaml`](https://raw.githubusercontent.com/frostmage1250/egern-config/main/Profile.yaml)
  is the Egern profile.
- `rules/*.yaml` are Egern-native YAML rule sets generated directly from text
  sources. Mihomo providers come from `appshubcc/bett-rules`; the APNs override
  comes from `ttyyss2233/Tool/shadowrocket/rules/apns.list`. MRS files are not
  converted.
- `reports/source.json` records immutable upstream commits, source hashes, entry
  counts, policy counts, and the generated profile hash.
- GitHub Actions refreshes the generated repository files every day and can also
  be run manually. The Egern profile itself deliberately has no root
  `auto_update`; re-import it manually when you want to replace the active profile.

## Subscription setup

Subscription credentials are deliberately not committed to this public repository.
After importing `Profile.yaml` into Egern, use Egern's **Add Subscription**
command and enter the airport URL. The profile sets `default_subscription_group`
to **订阅** and `default_proxy_group` to **Proxy**, so the private URL remains in
Egern instead of the public repository. Region groups flatten and filter **订阅**,
so future node changes continue to flow into 台湾、新加坡、日本、美国、其他节点
and 低倍率节点 automatically. Telegram and 媒体 also expose 订阅 as an
additional selectable policy. Because a full profile replacement overwrites
locally added subscription URLs, profile updates are manual; remote rule sets and
the locally configured node subscription can still update independently.

## Migration behavior

The generator reads the current Mihomo script on every run and preserves its rule
order, policies, region filters, service groups, DNS choices, and Hosts mappings.
The requested APNs override is the sole rule inserted ahead of the Mihomo rules:
its classical domain/IPv4/IPv6 entries are converted into `rules/apns.yaml`,
routed through `Proxy`, and placed first in DNS Forward with `Foreign`.
Mihomo `default-nameserver` endpoints are converted to the same IP addresses in
Egern `bootstrap` (plain UDP is required by Egern). Mihomo `nameserver-policy`
and every explicit Direct domain rule become ordered Egern DNS Forward rules that
use `system`; the foreign DNS group remains the final catch-all. No
`real_ip_domains` field is generated; Fake-IP behavior is left to Egern's native
defaults. MESL private DNS is used only as Egern `proxy_nameservers`, while normal
DNS forwarding stays separate. Egern cannot reproduce Mihomo's runtime
`direct-nameserver` re-resolution when a selectable policy group is switched to
Direct, so the generator preserves every statically identifiable Direct domain
rule and records that platform boundary in `reports/source.json`.

The only deliberate platform mapping is that Mihomo's IPv4/IPv6-preferred DIRECT
pseudo-proxies become Egern's built-in `DIRECT`; Egern has no equivalent
per-DIRECT-policy IP-version selector.
