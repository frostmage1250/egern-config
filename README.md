# Egern configuration

This repository translates the published configuration model from
[`frostmage1250/mihomo-script`](https://github.com/frostmage1250/mihomo-script)
into [`Profile.yaml`](https://raw.githubusercontent.com/frostmage1250/egern-config/main/Profile.yaml).

## Routing contract

**APNs follows the shared blocking stage.** Its rule uses `Proxy`.
The foreign DoH endpoints `cloudflare-dns.com` and `dns.google` use explicit
`Proxy` domain rules at the start, translating Mihomo's `#Proxy` DNS bindings.
The independent `privaterelay.yaml`
rule is retained immediately before Bett Apple and also uses `Proxy`.
All shared rules are a one-to-one syntax translation of the pinned Mihomo
effective `main()` output, preserving order, duplicate occurrences, and `no-resolve`
flags. Policy mappings are Mihomo `pron` to Egern `porn`, and the former
`Apple Podcasts` target to `媒体`, and `Direct` to built-in `DIRECT`;
group references use the same mappings. The `Direct` group is not emitted. The generator never independently moves Private, MCDN,
Claude/AI, Steam, or any other business rule. Service targets follow the source
with the declared policy mappings applied.

The Egern policy group is named `porn`. The independent Private Relay
rule is fetched, hash/count verified, and
referenced explicitly; it is retained separately from the shared Bett Apple.
The renamed rule-set is `porn.yaml` with provider key `porn`; its existing
policy group is also named `porn`.

Validation reverses the generated rules into Mihomo rule strings and compares
the shared list with the source after applying the declared policy mappings and
checking the DNS endpoint prefix and both other Egern additions.
Reordering, extra or missing rules, policy changes outside the declared mappings, and changed `no-resolve` flags fail the build.
`reports/source.json` records this source rule list and the Egern additions.

## Subscriptions and Egern settings

Virtual-interface-only mode is enabled by default with `vif_only: true`.

Subscription credentials stay local. After importing the profile, add your URL
to **订阅**. **订阅2** starts with empty `policies` and `urls` and uses the same
node exclusion filter. The profile keeps `default_subscription_group: 订阅`
and `default_proxy_group: 代理`.

Proxy retains subscription and regional groups as selectable entries with
`flatten: false`. Every regional group, 其他节点, and
低倍率节点 filters nodes from both 订阅 and 订阅2. Telegram and 媒体 expose both
subscriptions. 媒体 also offers 美国 and 日本 as selectable policy groups.
Region/exclusion patterns come from the pinned Mihomo model; the low-rate
filter additionally matches `实验`. EHentai adds `美国`, `新加坡`, and
`低倍率节点` to its existing choices. The porn group offers `香港`, `新加坡`,
`美国`, and `低倍率节点`. YouTube is rendered
at its source group position with its source policy choices, rather than being
discarded and reconstructed after 媒体.

Profile replacement remains manual to preserve locally entered subscription
URLs; no root `auto_update` is emitted. Remote rule sets and subscriptions can
update independently. DNS hijacking, all-network/APNs inclusion, closing old
connections on policy changes, the real-IP exclusion list, and subscription defaults remain existing Egern
settings. Shared DNS and Hosts follow the current published Mihomo script,
with the previously reviewed MESL private DNS, Flower node aliases, and AliDNS
Hosts preserved as explicit provider overrides. Changes to shared upstream
configuration must retain these provider settings.

## DNS mapping

DNS Forward first maps the fixed DIRECT domain prefix to `system`: explicit
domains/suffixes plus Private, geolocation-cn, Steam CN, NVIDIA CN, Apple CN,
and Microsoft CN. These entries take priority over the shared DNS policy,
including Douyin. The builder derives them from the pinned traffic rules and
rejects domain DIRECT rules placed after business rules to avoid overriding
earlier proxy matches. IP-only CN/private fallback rules cannot select DNS
before resolution and do not produce Forward entries.

Remaining queries follow Mihomo's `nameserver-policy` in source order: Private uses
`system`, Douyin uses `system` plus `180.184.1.1` and `180.184.2.2`, and CN uses
`system`. Unmatched queries use the default foreign nameservers. APNs and Apple
Podcasts have no independent DNS override. Manually selecting DIRECT inside a
policy group does not change DNS Forward; only fixed domain DIRECT rules do.

Proxy DNS retains the two private DoH endpoints from the reviewed official
`MESL.yaml` (`dns.nameserver`), in reference order:

- `https://zone.rlose.com:39933/api-query`
- `https://radar.rlose.com/api-query`

These override generic Mihomo `proxy-server-nameserver` and are emitted as
Egern `dns.proxy_nameservers`; Egern connects to them directly. The custom
port, paths and order are preserved. Hosts merge the current shared mappings
with the three reviewed Flower node aliases and the AliDNS addresses
`223.5.5.5` and `223.6.6.6` for `dns.alidns.com`. Provider aliases take priority
over conflicting shared entries. Node credentials are not included.

These settings were recovered from the reviewed configuration at commit
`f04f307d2d7a8a4e3e2b4ddbc109c03b1a871c85`, before commit `f09b731` removed them.
The generated report records their provenance under
`dns.proxy_nameservers_source` and `dns.hosts_overrides`.

Mihomo `default-nameserver` IPs retain source order in Egern's plain-UDP
bootstrap. Foreign resolver URLs retain their server order. Egern does not support
Mihomo's `#Proxy` DNS routing suffix, so the generator removes it from the URLs
and emits exact domain rules for `cloudflare-dns.com` and `dns.google` targeting
`Proxy` before all shared routing rules. Ordinary Egern DNS upstream connections
follow those explicit routes, matching Mihomo's selected Proxy group rather
than a service group or Final. Proxy-DNS connections and Bootstrap remain direct.
Selecting DIRECT inside Proxy still makes these connections direct, as in Mihomo.
Other DNS routing suffixes fail explicitly instead of being silently dropped.

Existing Hosts mappings still take precedence over DNS Forward. Egern cannot
reproduce Mihomo's runtime `direct-nameserver` re-resolution
after a selectable policy switches to DIRECT. IPv4/IPv6-preferred DIRECT
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

Apple Podcasts uses the `媒体` policy group, with no independent select group.
The former source target maps to `媒体` until the converter snapshot catches up.
Bett's `apple-podcasts` native rule set follows the pinned Mihomo order,
in the business stage before Apple, following Microsoft and AppleTV. Its DNS first
uses system DNS for domains covered by the fixed DIRECT prefix, then follows
the shared nameserver policy and the default foreign nameservers. Mihomo additionally uses
system DNS at the direct exit when selected; Egern cannot reproduce that
runtime re-resolution. General Apple uses Bett's `apple` source through the current upstream
mirror; the former `apple-merged` provider is retired.

## DNS and Hosts source

Routing stays pinned to the converter manifest's Mihomo commit. DNS and Hosts
are extracted together from a separately pinned current Mihomo commit, recorded
at `reports/source.json` → `dns.mihomo_script`. This prevents an older converter
snapshot from retaining retired DNS policies or Hosts mappings. The workflow
captures both commits once and downloads each script by its immutable SHA.

The extractor runs the shared source with placeholder nodes and empty input DNS/Hosts.
It captures the published script's base output; it does not process private
subscription credentials or reproduce subscription-specific runtime DNS changes.
Egern's DNS routing, Bootstrap transport, and Direct re-resolution have the
platform limits described above; this is a source-data translation rather than
identical resolver behavior.

## Foreign QUIC control

The profile keeps global `block_quic: false` and translates the Mihomo
`UDP AND destination port 443 AND NOT (cn_additional OR cn_ip)` rule at
the YAML-derived source position: upstream direct prefix, then foreign QUIC,
MCDN rejection, APNs, and business routing. The nested CN IP condition retains `no_resolve: true`.

The logical rule is named **屏蔽国外 QUIC** and starts with `disabled: false`.
Set that rule's `disabled` to `true` to allow this traffic to follow ordinary
routing, or to `false` to enable blocking again. Keep the App's global QUIC
block switch off for this selective mode. Explicit QUIC blocking on imported
nodes or policy groups takes precedence over the global setting; use
`block_quic: false` there when those connections should allow QUIC.

Both CN exception rule sets use the converter's Egern YAML. The additional
CN set is decoded from the final upstream MRS URL with official Mihomo,
with the captured MRS digest recorded in the converter manifest.
Generation recursively validates nested provider references and reverses
the logical expression to verify source condition, flags, action, and order.

## YAML routing-order reference

Mihomo generation reads the upstream `Config/mihomoConfig.yaml` and
`Script/mihomoScript.js` from the same source archive. The shared prefix, QUIC placement, business order and
fallback order follow that YAML. The retained service additions are anchored:
Claude before AI; AppleTV and Podcasts before Apple; Twitch after YouTube.
The upstream domestic direct prefix precedes the service stage. MCDN occupies
the blocking stage immediately after QUIC. APNs uses Proxy just after that
blocking stage; Private Relay uses Proxy immediately before Apple.

The Mihomo extractor uses the public main entry point with reserved placeholder
nodes, so both pinned older scripts and the complete upstream runtime are supported.
Home groups use their source filters over both subscriptions. Low-rate and high-rate
subscription exclusions follow their independent source switches.
