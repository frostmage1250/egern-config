# Egern configuration

`main` independently reads the latest published `frostmage1250/mihomo-script/main/mihomoScript.js` once and executes it once with placeholder nodes. The temporary extraction stays on the runner. No configuration model is transferred from the rule converter.

Native rules are published separately by [proxy-rules-converter/egern](https://github.com/frostmage1250/proxy-rules-converter/tree/egern). The generator reads its small filename/source index once and checks required provider definitions before publishing. Rule bodies are converted and checked by that branch; this repository does not download them again.

## Customizations

All personal choices and DNS adaptation selections live in [custom/customizations.json](custom/customizations.json):

- Both subscriptions start with empty policies and URLs, and no explicit update interval. Credentials are entered locally.
- Filtered regional, rate, home and other groups read both subscriptions. Proxy retains selectable groups. Regional patterns and independent exclusion switches follow Mihomo; low-rate adds 实验.
- Service groups inherit source choices plus the listed additions. Porn uses the listed four choices.
- Direct and the IPv4/IPv6-preferred candidates are removed. Built-in direct action output is handled by format adaptation. No legacy pron, Apple Podcasts or Taiwan name aliases are applied.
- Foreign QUIC rejection is omitted and global block_quic stays false.
- APNs uses Proxy after the shared blocking stage. Private Relay uses Proxy immediately before Apple. Rule data belongs to the converter branch.
- Shared DNS/Hosts follow the same script snapshot. Fixed DIRECT domain prefixes use system DNS before source nameserver-policy and foreign fallback. DoH Proxy bindings become explicit endpoint routes. Bootstrap uses source IPs as plain UDP.
- Policy-group selection does not cause Mihomo-style direct-nameserver re-resolution; fixed-direct-prefix forwarding is the declared approximation.
- Reviewed MESL proxy DNS, Flower aliases, AliDNS IP additions and real-IP exclusions remain explicit.
- The profile stays manually updated to preserve local subscriptions. Remote native rule references update every 86400 seconds.

The workflow builds once, performs consolidated structural/reference validation, and publishes only [Profile.yaml](https://raw.githubusercontent.com/frostmage1250/egern-config/main/Profile.yaml). Three focused adapter regressions run on source pushes, without another generation pass. Historical `rules/*.yaml` remain frozen compatibility URLs for older profiles.
