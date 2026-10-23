# Egern configuration

This repository translates the published configuration model from
[`frostmage1250/mihomo-script`](https://github.com/frostmage1250/mihomo-script)
into [`Profile.yaml`](https://raw.githubusercontent.com/frostmage1250/egern-config/main/Profile.yaml).

## Routing contract

**APNs is the only exception.** One APNs rule using `Proxy` is first. Every
remaining rule is a one-to-one syntax translation of the pinned Mihomo
`finalRules` list, preserving order, duplicate occurrences, target policy names,
and `no-resolve` flags. The generator never independently moves Private, MCDN,
Claude/AI, Steam, or any other business rule. It never rewrites YouTube,
AppleTV, or bypass-japan target policies.

The `pron` policy name follows Mihomo literally. The former Egern-only `porn`
rename is removed. There is no extra Private Relay routing reference; optional
converter-only artifacts remain available in the converter repository but are
not downloaded, loaded, or inserted here. Private Relay coverage supplied by
Mihomo's shared Apple rule set continues to follow that source.

Validation reverses the generated rules into Mihomo rule strings and compares
the entire list with the unmodified source. Reordering, extra or missing
rules, changed policies, and changed `no-resolve` flags fail the build.
`reports/source.json` records this source rule list and the sole APNs exception.

## Subscriptions and Egern settings

Subscription credentials stay local. After importing the profile, add your URL
to **订阅**. **订阅2** starts with empty `policies` and `urls` and uses the same
node exclusion filter. The profile keeps `default_subscription_group: 订阅`
and `default_proxy_group: 代理`.

Proxy flattens both subscription groups. Hong Kong filters both; the other
regional and low-rate groups filter 订阅. Telegram and 媒体 expose both
subscriptions. Region/exclusion patterns come from the pinned Mihomo model.
The pron group retains Hong Kong and Singapore as choices. YouTube is rendered
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
explicit error requiring a corresponding rule in Mihomo; it cannot create a
second Egern routing exception.

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
pins that converter commit and the manifest's Mihomo commit. It downloads only
APNs and providers referenced by Mihomo routing/DNS, checking each file's hash,
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
