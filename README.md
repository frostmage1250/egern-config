# Egern configuration

This repository migrates the current behavior of
[`frostmage1250/mihomo-script`](https://github.com/frostmage1250/mihomo-script)
to an Egern profile.

- [`Profile.yaml`](https://raw.githubusercontent.com/frostmage1250/egern-config/main/Profile.yaml)
  is the Egern profile.
- `rules/*.yaml` are Egern-native YAML rule sets generated directly from the text
  sources in `appshubcc/bett-rules`; MRS files are not converted.
- `reports/source.json` records immutable upstream commits, source hashes, entry
  counts, policy counts, and the generated profile hash.
- GitHub Actions refreshes the repository every day and can also be run manually.

## Subscription setup

Subscription credentials are deliberately not committed to this public repository.
After importing `Profile.yaml` into Egern, use Egern's **Add Subscription**
command and enter the airport URL. The profile sets `default_subscription_group`
to **订阅** and `default_proxy_group` to **Proxy**, so the private URL remains in
Egern instead of the public repository. Region groups flatten and filter **订阅**,
so future node changes continue to flow into 台湾、新加坡、日本、美国、其他节点
and 低倍率节点 automatically.

## Migration behavior

The generator reads the current Mihomo script on every run and preserves its rule
order, policies, region filters, service groups, DNS choices, Fake-IP exclusions,
and Hosts mappings. Mihomo's `fakeip_filter` is expanded into Egern's
`real_ip_domains` together with Mihomo's `private` and `geolocation-cn` exclusions. A bare `*` is intentionally omitted because Egern would treat it as every domain and disable Fake-IP globally. MESL private DNS is used only as Egern
`proxy_nameservers`, while normal DNS forwarding stays separate.

The only deliberate platform mapping is that Mihomo's IPv4/IPv6-preferred DIRECT
pseudo-proxies become Egern's built-in `DIRECT`; Egern has no equivalent
per-DIRECT-policy IP-version selector.
