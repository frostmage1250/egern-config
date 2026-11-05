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

The manifest additionally retains the 15 explicit real-IP domain exceptions,
the 实验 supplement for the 低倍率节点 filter, and an empty 订阅2 group immediately
after 手动选择. Both subscription groups feed the dynamic node filters and replace
the manual subscription choice wherever it is referenced.
No service exclusion, policy alias, or former service candidate/order override
is retained. The manifest also restores the two MESL proxy DNS endpoints and
three Flower hostname aliases. MESL proxy DNS applies to all proxy hostnames.

## Native adaptation

Group names/order/icons/visibility and routing order come from the source.
select stays select; url-test becomes auto_test; load-balance becomes native
destination-hash load_balance. Source intervals/tolerances are preserved where
supported; timeout milliseconds become seconds.

Enter subscription URLs locally in the upstream 手动选择 group (initially empty).
Groups that enumerate subscription nodes use native flatten/filter against this
group and 订阅2, including regional/rate/home/other groups. Source filters are
preserved with the explicit 实验 supplement for 低倍率节点.

Egern has no native Mihomo direct-proxy variants: their candidates map to DIRECT.
Unsupported REJECT-DROP/PASS group choices are omitted; the source rule actions
are otherwise unchanged. The AdBlock group retains REJECT. PROCESS-NAME rules are omitted because Egern
on iOS exposes no process matcher; Emby's domain rules remain active. Native flattening of
dynamic node lists does not preserve every nested group as a selectable item.
Mihomo-only group fields (lazy, max-failed-times, empty-fallback,
default-selected, exclude-type) have no exact native equivalent and are omitted.

DNS forwarding policies, default foreign DNS, endpoint routing suffixes,
and base hosts come from the source. The explicit MESL proxy DNS list replaces
the inherited proxy DNS list; the three Flower aliases overlay source hosts. Bootstrap is derived from source startup IPs as
plain UDP because Egern bootstrap accepts only UDP IPs. Mihomo +. hosts become
an apex mapping plus a *. wildcard mapping. The old system-DNS direct-prefix
override and AliDNS additions remain removed.

Mihomo's rule-set-based fake-ip-filter and direct-nameserver re-resolution have
no equivalent in this static native profile. Only literal source Fake-IP
exceptions map to real_ip_domains and are merged, without duplicates, with the
15 retained Egern exceptions. These affect DNS answers, not routing policy.
Egern-only defaults apply to unsupported platform/global fields. Supported IPv6,
LAN access, tunnel mode and DNS hijacking fields inherit the source. A global
QUIC block stays off; any source selective QUIC rules are translated normally.

The workflow performs one generation and its integrated structural/reference
validation before publishing. No local tests, model artifact, or extra test stage
is required.
