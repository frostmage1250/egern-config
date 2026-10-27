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
connections on policy changes, the real-IP exclusion list,
AliDNS host additions, and the Flower host aliases remain existing Egern
settings. These do not insert or reorder routing rules.

## DNS mapping

DNS Forward follows Mihomo's `nameserver-policy` in source order: Private uses
`system`, Douyin uses `system` plus `180.184.1.1` and `180.184.2.2`, and CN uses
`system`. Unmatched queries use the default foreign nameservers. APNs and Apple
Podcasts have no independent DNS override. Traffic rules targeting Direct do
not synthesize DNS Forward entries; traffic policy selection and DNS matching
remain separate, as in Mihomo.

Node resolution uses Mihomo's `proxy-server-nameserver`, preserving protocol,
server order, and duplicates while removing the `#DIRECT` routing suffix.
The previous fixed MESL resolver list is removed. Per-node DNS policies fail
explicitly because this static profile cannot represent subscription-dependent
Mihomo `proxy-server-nameserver-policy`.

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

The independent `Apple Podcasts` select group inherits its choices from Mihomo,
adds `媒体` as a selectable policy group, and defaults to `Proxy`.
Bett's `apple-podcasts` native rule set is placed before
Apple CN. Its DNS follows the shared nameserver policy, including CN/system when a domain
matches CN, then the default foreign nameservers. Mihomo additionally uses
system DNS at the direct exit when selected; Egern cannot reproduce that
runtime re-resolution. General Apple uses Bett's `apple` source through the current upstream
mirror; the former `apple-merged` provider is retired.

## DNS audit (2026-10-27)

Compared published Mihomo commit `21c52a92b2f4d851340a12facb3671d2bcfebe57`
with the current upstream script at `071d4ec5764b4700d0c5de41797f20a8bdf6b6d8`.
The retained `Script/mihomoScript.js` matches upstream SHA-256
`55ae4b64b24f05568da69531dae20037092c3f9ca22dcbaedc6a203d00579e05`.
DNS resolver selection matches after the intentional CN/direct `system`
replacements and the `默认代理` to `Proxy` name mapping. Six VM comparisons cover
empty input, private resolvers, node-domain policy, proxy-server policy, local
listener/hosts rewriting, and private node resolvers.

This conclusion concerns resolver selection. The full DNS configuration retains
additional Repcz Fake-IP exclusions, excludes optional FCM filtering, and uses
custom hosts/provider data. Those are existing differences from upstream.
Egern bootstrap remains plain UDP because its bootstrap field accepts IPs;
Mihomo's TLS/HTTPS bootstrap transport and runtime Direct re-resolution cannot
be reproduced exactly. Routing stays pinned to the converter manifest's Mihomo commit. DNS is extracted
from a separately pinned current Mihomo commit, recorded at
`reports/source.json` → `dns.mihomo_script`; this prevents an older converter
snapshot from retaining retired DNS policies. The workflow captures both commits
once and downloads each script by its immutable SHA.
