# Egern configuration

Profile: [Profile.yaml](https://raw.githubusercontent.com/frostmage1250/egern-config/main/Profile.yaml).

## Generation

Read the latest published frostmage1250/mihomo-script/main/mihomoScript.js once,
extract its active configuration once, translate to native Egern fields, then
publish Profile.yaml. The source model exists only in the runner's temporary
directory. It is independently extracted, not shared by the converter.

Native rule bodies are published by proxy-rules-converter/egern. Read its small
source/filename index once and require matching provider URLs, behaviors and
formats before publication. Historical rules/*.yaml in this repository remain
frozen compatibility URLs and are not used by the generated profile.

## Retained customization list

The shared script owns Claude, porn, AppleTV, Apple Podcasts, and the MCDN
REJECT action. TV and Podcasts precede apple_cn; Claude precedes AI; porn follows
EHentai. The manifest applies the following Egern-only customizations.

### Profile and routing

- Force IPv6 and virtual-interface-only mode on.
- Derive DNS hijacking from the source tun.dns-hijack list. Paired any:PORT
  (UDP) and tcp://any:PORT targets become the Egern address pattern '*:PORT'.
  The current source pair produces '*:53', not a bare '*'. Reject unsupported
  targets or protocol-only selections instead of copying foreign syntax or
  silently broadening their scope. There is no independent hijack override.
  Syntax reference: [maintainer's Egern configuration](https://github.com/Repcz/Tool/blob/X/Egern/Egern.yaml).
  This reference and generation checks are not a device-level runtime test.
- Enable close_connections_on_policy_change, include_all_networks and include_apns.
- Keep the global QUIC block off and omit the source's foreign QUIC blocking rules.
- Place MCDN blocking immediately before geolocation-cn, followed by APNs through
  代理 with no_resolve. APNs remains adjacent to MCDN when the block is relocated.
- Route Private Relay through 代理 immediately after the Microsoft domain rules.
- Restore default_subscription_group: 订阅 and default_proxy_group: 代理.
  Both defaults reference actual output groups.

### Groups

- Rename source 手动选择 to 订阅 and 默认代理 to 代理, including all references.
- Remove legacy Direct/source 直连 groups and map their references to built-in DIRECT.
- Keep 订阅 and 订阅2 empty in the published profile; enter subscription URLs locally.
  Both feed dynamic regional/rate/home/other node filters.
- Append 实验 to the 低倍率节点 filter.
- 代理: prepend 订阅, 订阅2; set flatten to false.
- Google and AI: append 订阅.
- Telegram: append 香港, 订阅, 订阅2.
- 媒体: append 香港, 订阅, 订阅2, 美国, 日本.
- PikPak: append 香港.
- EHentai: append 美国, 新加坡, 低倍率节点.
- porn: replace candidates with 香港, 新加坡, 美国, 低倍率节点.
- Omit IPv4优先 and IPv6优先 candidates throughout.

Candidate additions retain the first occurrence of duplicates. If the source
has no 媒体 group, insert it after Google with the former candidate order:
代理, 低倍率节点, 香港, 美国, 订阅, 订阅2, 日本.
Existing service routing targets otherwise follow the source.

### DNS and real-IP exceptions

- Replace inherited proxy DNS with the two MESL endpoints in the manifest.
  This applies to all proxy hostnames, not only MESL subscription nodes.
- Restore the three Flower hostname aliases.
- Merge the 15 retained Egern real-IP exceptions with literal source Fake-IP
  exceptions, without duplicates. This affects DNS answers, not routing policy.

The former fixed-direct-prefix system-DNS override is deliberately not restored.
DNS forwarding policies and default foreign DNS continue to follow the source.

## Native adaptation

Source group order, icons, visibility, service routing and supported parameters
are preserved subject to the explicit manifest aliases, removed groups and extra
groups. select stays select; url-test becomes auto_test; load-balance becomes
native load_balance. Source intervals/tolerances are preserved where supported;
timeout milliseconds become seconds.

Egern has no native Mihomo direct-proxy variants: their candidates map to DIRECT.
Unsupported REJECT-DROP/PASS group choices are omitted; the source rule actions
are otherwise unchanged. The AdBlock group retains REJECT. PROCESS-NAME rules
are omitted because Egern on iOS exposes no process matcher; Emby's domain rules
remain active. Dynamic flattening does not preserve every nested group as a
selectable item. Mihomo-only group fields lazy, max-failed-times, empty-fallback,
default-selected and exclude-type have no exact native equivalent and are omitted.

DNS endpoint routing suffixes and base hosts come from the source. Bootstrap
uses source startup IPs as plain UDP because Egern bootstrap accepts only UDP IPs.
Mihomo +. hosts become an apex mapping plus a *. wildcard mapping.
Rule-set-based fake-ip-filter and direct-nameserver re-resolution have no exact
equivalent in this static native profile.

The workflow performs one generation and its integrated structural/reference
validation before publishing. No local tests, model artifact, or extra test stage
is required.
