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

The shared script owns five additional providers and their native service groups:
Claude, porn, AppleTV, Apple Podcasts, and the MCDN REJECT action.
TV and Podcasts precede apple_cn; Claude precedes AI; porn follows EHentai.
MCDN blocking remains after the prefix/optional QUIC stage and before services.

Two Egern-only routes remain explicitly in custom/customizations.json:

- APNs: 默认代理, immediately after the MCDN REJECT rule, with no_resolve.
- Private Relay: 默认代理, immediately after the Microsoft domain rules.

APNs tunnel capture (include_all_networks/include_apns) remains enabled so that
the retained APNs route can receive the traffic.

No independent DNS server, hosts alias, real-IP exclusion list, service exclusion,
policy alias, group candidate/order override, low-rate regex supplement, or extra
subscription group is retained.

## Native adaptation

Group names/order/icons/visibility and routing order come from the source.
select stays select; url-test becomes auto_test; load-balance becomes native
destination-hash load_balance. Source intervals/tolerances are preserved where
supported; timeout milliseconds become seconds.

Enter subscription URLs locally in the upstream 手动选择 group (initially empty).
Groups that enumerate subscription nodes use native flatten/filter against this
group, including regional/rate/home/other groups. The source node filters are
translated without the retired 实验 supplement. No 订阅2 group is added.

Egern has no native Mihomo direct-proxy variants: their candidates map to DIRECT.
Unsupported REJECT-DROP/PASS group choices are omitted; the source rule actions
are otherwise unchanged. The AdBlock group retains REJECT. Native flattening of
dynamic node lists does not preserve every nested group as a selectable item.
Mihomo-only group fields (lazy, max-failed-times, empty-fallback,
default-selected, exclude-type) have no exact native equivalent and are omitted.

DNS forwarding policies, default foreign DNS, proxy DNS, endpoint routing suffixes,
and hosts come from the source. Bootstrap is derived from source startup IPs as
plain UDP because Egern bootstrap accepts only UDP IPs. Mihomo +. hosts become
an apex mapping plus a *. wildcard mapping. The old system-DNS direct-prefix
override, MESL proxy DNS, Flower aliases and AliDNS additions are removed.

Mihomo's rule-set-based fake-ip-filter and direct-nameserver re-resolution have
no equivalent in this static native profile. Only literal source Fake-IP
exceptions can map to real_ip_domains; no independent exception list is added.
Egern-only defaults apply to unsupported platform/global fields. Supported IPv6,
LAN access, tunnel mode and DNS hijacking fields inherit the source. A global
QUIC block stays off; any source selective QUIC rules are translated normally.

The workflow performs one generation and its integrated structural/reference
validation before publishing. No local tests, model artifact, or extra test stage
is required.
