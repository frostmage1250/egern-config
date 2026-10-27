# Egern configuration

This repository translates the published configuration model from
[`frostmage1250/mihomo-script`](https://github.com/frostmage1250/mihomo-script)
into [`Profile.yaml`](https://raw.githubusercontent.com/frostmage1250/egern-config/main/Profile.yaml).

## Routing contract

**APNs is first.** Its rule uses `Proxy`. The independent `privaterelay.yaml`
rule is retained immediately before Bett Apple and also uses `Proxy`.
All shared rules are a one-to-one syntax translation of the pinned Mihomo
`finalRules` list, preserving order, duplicate occurrences, and `no-resolve`
flags. The sole policy-name alias is Mihomo `pron` to Egern `porn`; rule targets
and references from other policy groups use the same alias. The generator never independently moves Private, MCDN,
Claude/AI, Steam, or any other business rule. Service targets follow the source
with the declared policy-name alias applied.

The Egern policy group is named `porn`. The independent Private Relay
rule is fetched, hash/count verified, and
referenced explicitly; it is retained separately from the shared Bett Apple.
The renamed rule-set is `porn.yaml` with provider key `porn`; its existing
policy group is also named `porn`.

Validation reverses the generated rules into Mihomo rule strings and compares
the shared list with the source after applying the declared name alias and
checking both Egern additions.
Reordering, extra or missing rules, policy changes outside the declared alias, and changed `no-resolve` flags fail the build.
`reports/source.json` records this source rule list and both approved Egern additions.

## Subscriptions and Egern settings

Subscription credentials stay local. After importing the profile, add your URL
to **订阅**. **订阅2** starts with empty `policies` and `urls` and uses the same
node exclusion filter. The profile keeps `default_subscription_group: 订阅`
and `default_proxy_group: 代理`.

Proxy flattens both subscription groups. Every regional group, 其他节点, and
低倍率节点 filters nodes from both 订阅 and 订阅2. Telegram and 媒体 expose both
subscriptions. 媒体 also offers 美国 and 日本 as selectable policy groups.
Region/exclusion patterns come from the pinned Mihomo model.
The porn group retains Hong Kong and Singapore as choices. YouTube is rendered
at its source group position with its source policy choices, rather than being
discarded and reconstructed after 媒体.

Profile replacement remains manual to preserve locally entered subscription
URLs; no root `auto_update` is emitted. Remote rule sets and subscriptions can
update independently. DNS hijacking, all-network/APNs inclusion, closing old
connections on policy changes, the real-IP exclusion list, MESL proxy DNS,
AliDNS host additions, and the Flower host aliases remain existing Egern
settings. These do not insert or reorder routing rules.

## DNS mapping

APNs is also first in DNS Forward, using `Foreign`. Mihomo
`nameserver-policy` becomes ordered Egern DNS Forward rules with the same server
lists, including `system`. Statically Direct domain matchers add `system`
forwarding before the foreign catch-all, except when an explicit DNS policy
already handles that provider. This avoids a second unreachable generated
entry while retaining source duplicates and explicit DNS policy precedence.

Mihomo `default-nameserver` IPs retain source order in Egern's plain-UDP
bootstrap. Foreign resolver URLs retain their server order. The two existing
excluded DoH endpoints, cloudflare-dns.com and dns.google, keep their clean
URLs without injected routing rules. Any new DNS routing suffix fails with an
explicit error requiring a corresponding rule in Mihomo; it cannot create any additional Egern endpoint rules.

Egern cannot reproduce Mihomo's runtime `direct-nameserver` re-resolution
after a selectable policy switches to Direct. IPv4/IPv6-preferred DIRECT
pseudo-proxies map to Egern's built-in DIRECT. Other Fake-IP behavior follows
Egern defaults and the existing explicit real-IP exclusions.

## Generation and environment

A single GitHub Actions workflow runs every six hours or manually. Python 3.13
with the sole Python dependency `PyYAML==6.0.3` renders YAML and verifies rule
artifacts. Node 24 executes the pinned Mihomo model extractor in a VM; it needs
no npm dependencies. The workflow uses one setup step for each runtime.

[`proxy-rules-converter`](https://github.com/frostmage1250/proxy-rules-converter/tree/main/dist/egern)
publishes native rule sets and `reports/egern-source.json` first. This repository
pins that converter commit and the manifest's Mihomo commit. It downloads
APNs, standalone Private Relay, and providers referenced by Mihomo routing/DNS,
checking each file's hash,
entry count, and native-field-order digest. There is no separate inline
Apple/Private Relay assertion block in the workflow duplicating the generator's
manifest validation.

The profile references stable converter `main/dist/egern/*.yaml` URLs with
86400-second updates. Each provider has one YAML file. The converter preserves
counts, duplicates, and within-type order; native YAML cannot express original
interleaving between different rule types.

After generation and the consolidated test suite, Actions commits only
`Profile.yaml` and `reports/source.json` and verifies their remote publication.
Historical `rules/*.yaml` files remain read-only compatibility paths for
previously imported profiles; they are not inputs or outputs of this generator.

## Apple Podcasts

The independent `Apple Podcasts` select group inherits its choices from Mihomo
and defaults to `Proxy`. Bett's `apple-podcasts` native rule set is placed before
Apple CN. Its DNS forwarding inherits the foreign upstreams before CN/system
matching. General Apple uses Bett's `apple` source through the current upstream
mirror; the former `apple-merged` provider is retired.
