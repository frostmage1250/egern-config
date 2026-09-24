from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from build_egern import (  # noqa: E402
    BuildError,
    bootstrap_nameservers,
    nameservers,
    parse_classical_rule_list,
    parse_classical_yaml_provider,
    parse_domain_list,
    parse_ip_list,
    referenced_providers,
    render_dns_forward,
    render_nameserver_route_rules,
    render_policy_groups,
    render_rules,
    resolve_provider_source,
    source_rule_count,
    output_rule_count,
    validate_business_ip_pairs,
)


class EgernBuilderTests(unittest.TestCase):
    def test_domain_source_becomes_native_egern_fields(self):
        result = parse_domain_list(
            "example.com\n+.example.net\nkeyword:video\nregexp:^api\\.\n*.local\n"
        )
        self.assertEqual(result["domain_set"], ["example.com"])
        self.assertEqual(result["domain_suffix_set"], ["example.net"])
        self.assertEqual(result["domain_keyword_set"], ["video"])
        self.assertEqual(result["domain_regex_set"], ["^api\\."])
        self.assertEqual(result["domain_wildcard_set"], ["*.local"])

    def test_ip_source_splits_v4_and_v6_and_sets_no_resolve(self):
        result = parse_ip_list("1.1.1.1/24\n2001:db8::1/32\n")
        self.assertTrue(result["no_resolve"])
        self.assertEqual(result["ip_cidr_set"], ["1.1.1.1/24"])
        self.assertEqual(result["ip_cidr6_set"], ["2001:db8::1/32"])

    def test_classical_apns_source_becomes_one_native_mixed_rule_set(self):
        result = parse_classical_rule_list(
            "DOMAIN-SUFFIX,push.apple.com\n"
            "DOMAIN-KEYWORD,apple.com.edgekey.net\n"
            "IP-CIDR,17.249.0.0/16,no-resolve\n"
            "IP-CIDR6,2620:149:a44::/48,no-resolve\n"
            "IP-ASN,399358,no-resolve\n"
        )
        self.assertEqual(result["domain_suffix_set"], ["push.apple.com"])
        self.assertEqual(
            result["domain_keyword_set"], ["apple.com.edgekey.net"]
        )
        self.assertEqual(result["ip_cidr_set"], ["17.249.0.0/16"])
        self.assertEqual(result["ip_cidr6_set"], ["2620:149:a44::/48"])
        self.assertEqual(result["asn_set"], ["399358"])
        self.assertTrue(result["no_resolve"])

    def test_classical_yaml_provider_preserves_payload_and_requires_no_resolve(self):
        result, count = parse_classical_yaml_provider(
            "payload:\n"
            "  - DOMAIN-SUFFIX,claude.ai\n"
            "  - DOMAIN-KEYWORD,sentry\n"
            "  - IP-CIDR,160.79.104.0/21,no-resolve\n"
            "  - IP-CIDR6,2607:6bc0::/32,no-resolve\n"
            "  - IP-ASN,399358,no-resolve\n"
        )
        self.assertEqual(count, 5)
        self.assertEqual(result["domain_suffix_set"], ["claude.ai"])
        self.assertEqual(result["domain_keyword_set"], ["sentry"])
        self.assertEqual(result["ip_cidr_set"], ["160.79.104.0/21"])
        self.assertEqual(result["ip_cidr6_set"], ["2607:6bc0::/32"])
        self.assertEqual(result["asn_set"], ["399358"])
        self.assertTrue(result["no_resolve"])
        with self.assertRaises(BuildError):
            parse_classical_yaml_provider(
                "payload:\n  - IP-ASN,399358\n"
            )

    def test_provider_source_follows_final_url_not_bundle_path(self):
        provider = {
            "path-in-bundle": "geo/geosite/geolocation-cn.mrs",
            "url": (
                "https://raw.githubusercontent.com/frostmage1250/"
                "proxy-rules-converter/main/dist/mihomo/geolocation-cn.mrs"
            ),
        }
        result = resolve_provider_source(
            provider,
            bett_commit="bett-commit",
            converter_commit="converter-commit",
        )
        self.assertEqual(result["repository"], "frostmage1250/proxy-rules-converter")
        self.assertEqual(result["ref"], "main")
        self.assertEqual(result["commit"], "converter-commit")
        self.assertEqual(result["path"], "dist/mihomo/geolocation-cn.list")
        self.assertEqual(
            result["url"],
            "https://raw.githubusercontent.com/frostmage1250/"
            "proxy-rules-converter/converter-commit/"
            "dist/mihomo/geolocation-cn.list",
        )

    def test_converter_classical_provider_uses_pinned_yaml(self):
        provider = {
            "url": (
                "https://raw.githubusercontent.com/frostmage1250/"
                "proxy-rules-converter/main/dist/mihomo/claude.yaml"
            ),
        }
        result = resolve_provider_source(
            provider,
            bett_commit="bett-commit",
            converter_commit="converter-commit",
        )
        self.assertEqual(result["repository"], "frostmage1250/proxy-rules-converter")
        self.assertEqual(result["commit"], "converter-commit")
        self.assertEqual(result["path"], "dist/mihomo/claude.yaml")
        self.assertTrue(result["url"].endswith("/converter-commit/dist/mihomo/claude.yaml"))

    def test_bett_provider_source_uses_final_url_and_pinned_commit(self):
        provider = {
            "path-in-bundle": "ignored/by/source/resolver.mrs",
            "url": (
                "https://fastly.jsdelivr.net/gh/appshubcc/"
                "bett-rules@meta/geo/geosite/google.mrs"
            ),
        }
        result = resolve_provider_source(
            provider,
            bett_commit="bett-commit",
            converter_commit="converter-commit",
        )
        self.assertEqual(result["repository"], "appshubcc/bett-rules")
        self.assertEqual(result["ref"], "meta")
        self.assertEqual(result["commit"], "bett-commit")
        self.assertEqual(result["path"], "geo/geosite/google.list")

    def test_rule_conversion_preserves_duplicates_spelling_and_count(self):
        domain_source = "example.com\n+.example.net\n+.example.net\n"
        domain_rule = parse_domain_list(domain_source)
        self.assertEqual(
            domain_rule["domain_suffix_set"],
            ["example.net", "example.net"],
        )
        self.assertEqual(source_rule_count(domain_source), output_rule_count(domain_rule))

        ip_source = "1.1.1.1/24\n1.1.1.1/24\n"
        ip_rule = parse_ip_list(ip_source)
        self.assertEqual(ip_rule["ip_cidr_set"], ["1.1.1.1/24", "1.1.1.1/24"])
        self.assertEqual(source_rule_count(ip_source), output_rule_count(ip_rule))

    def test_rules_preserve_order_and_no_resolve(self):
        model = {
            "rules": [
                "DOMAIN-SUFFIX,example.com,Direct",
                "RULE-SET,domain,Proxy",
                "RULE-SET,ip,Direct,no-resolve",
                "MATCH,Final",
            ]
        }
        rules = render_rules(model, {"domain": "domain.yaml", "ip": "ip.yaml"})
        self.assertEqual(
            rules[0]["rule_set"]["match"],
            "https://raw.githubusercontent.com/frostmage1250/egern-config/main/rules/apns.yaml",
        )
        self.assertEqual(rules[0]["rule_set"]["policy"], "Proxy")
        self.assertTrue(rules[0]["rule_set"]["no_resolve"])
        self.assertEqual(list(rules[1]), ["domain_suffix"])
        self.assertEqual(rules[2]["rule_set"]["policy"], "Proxy")
        self.assertTrue(rules[3]["rule_set"]["no_resolve"])
        self.assertEqual(list(rules[-1]), ["default"])

    def test_business_ip_pairs_require_adjacency_and_no_resolve(self):
        valid = {
            "providers": {
                "service": {"behavior": "domain"},
                "service_ip": {"behavior": "ipcidr"},
                "cn_ip": {"behavior": "ipcidr"},
            },
            "rules": [
                "RULE-SET,service,Proxy",
                "RULE-SET,service_ip,Proxy,no-resolve",
                "RULE-SET,cn_ip,Direct",
                "MATCH,Final",
            ],
        }
        validate_business_ip_pairs(valid)
        missing_flag = {
            **valid,
            "rules": [
                "RULE-SET,service,Proxy",
                "RULE-SET,service_ip,Proxy",
                "MATCH,Final",
            ],
        }
        with self.assertRaises(BuildError):
            validate_business_ip_pairs(missing_flag)
        separated = {
            **valid,
            "rules": [
                "RULE-SET,service,Proxy",
                "DOMAIN-SUFFIX,example.com,Proxy",
                "RULE-SET,service_ip,Proxy,no-resolve",
                "MATCH,Final",
            ],
        }
        with self.assertRaises(BuildError):
            validate_business_ip_pairs(separated)

    def test_nameserver_policy_suffixes_become_explicit_routing_rules(self):
        model = {
            "dns": {
                "nameserver": [
                    "https://cloudflare-dns.com/dns-query#Proxy",
                    "https://dns.google/dns-query#Proxy",
                    "1.1.1.1#DIRECT",
                ]
            },
            "rules": ["MATCH,Final"],
        }
        expected = [
            {
                "domain": {
                    "match": "cloudflare-dns.com",
                    "policy": "Proxy",
                }
            },
            {
                "domain": {
                    "match": "dns.google",
                    "policy": "Proxy",
                }
            },
            {
                "ip_cidr": {
                    "match": "1.1.1.1/32",
                    "policy": "DIRECT",
                    "no_resolve": True,
                }
            },
        ]
        self.assertEqual(
            nameservers(model),
            [
                "https://cloudflare-dns.com/dns-query",
                "https://dns.google/dns-query",
                "1.1.1.1",
            ],
        )
        self.assertEqual(render_nameserver_route_rules(model), expected)
        self.assertEqual(render_rules(model, {})[1:4], expected)

    def test_nameserver_policy_suffix_cannot_be_silently_dropped(self):
        with self.assertRaises(BuildError):
            nameservers({"dns": {"nameserver": ["https://dns.example/dns-query#"]}})
        with self.assertRaises(BuildError):
            render_nameserver_route_rules(
                {
                    "dns": {
                        "nameserver": [
                            "https://dns.example/dns-query#Proxy",
                            "https://dns.example/dns-query#DIRECT",
                        ]
                    }
                }
            )

    def test_groups_keep_subscription_private_and_region_filters_dynamic(self):
        model = {
            "regions": [
                {"name": "香港", "source": "HK|香港", "flags": "i"},
                {"name": "日本", "source": "JP|日本", "flags": "i"},
            ],
            "rateRegions": [
                {"name": "低倍率节点", "source": "0\\.5x", "flags": "i"}
            ],
            "excludeFilter": {"source": "traffic|到期", "flags": "iu"},
            "options": {"过滤非地区节点": True, "过滤低倍率节点": False},
            "groups": [
                {"name": "Proxy", "proxies": ["订阅", "日本"]},
                {"name": "订阅", "proxies": ["__SUBSCRIPTION__"]},
                {"name": "Direct", "proxies": ["DIRECT", "IPv4优先", "IPv6优先"]},
                {"name": "GitHub", "proxies": ["Proxy", "订阅", "AI"]},
                {"name": "Claude", "proxies": ["Proxy", "日本", "其他节点"]},
                {"name": "AI", "proxies": ["Proxy", "日本", "其他节点"]},
                {"name": "日本", "proxies": ["__日本__"]},
                {"name": "其他节点", "proxies": ["__其他节点__"]},
                {"name": "低倍率节点", "proxies": ["__低倍率节点__"]},
                {"name": "Telegram", "proxies": ["Proxy", "低倍率节点"]},
                {"name": "媒体", "proxies": ["Proxy", "低倍率节点"]},
                {"name": "Final", "proxies": ["Proxy", "Direct"]},
            ],
        }
        groups, filters = render_policy_groups(model)
        by_name = {
            next(iter(item.values()))["name"]: next(iter(item.values()))
            for item in groups
        }
        self.assertEqual(by_name["订阅"]["urls"], [])
        self.assertEqual(by_name["Direct"]["policies"], ["DIRECT"])
        self.assertEqual(by_name["GitHub"]["policies"], ["Proxy", "订阅", "AI"])
        self.assertEqual(by_name["Claude"]["policies"], ["Proxy", "日本", "其他节点"])
        self.assertEqual(by_name["日本"]["policies"], ["订阅"])
        self.assertTrue(by_name["日本"]["flatten"])
        self.assertEqual(
            by_name["Telegram"]["policies"], ["Proxy", "低倍率节点", "订阅"]
        )
        self.assertEqual(
            by_name["媒体"]["policies"], ["Proxy", "低倍率节点", "订阅"]
        )
        self.assertIn("traffic", filters["订阅"])

    def test_bootstrap_preserves_mihomo_default_nameserver_ips(self):
        model = {
            "dns": {
                "default-nameserver": [
                    "114.114.114.114#DIRECT",
                    "tls://223.5.5.5#DIRECT",
                    "https://1.12.12.12#DIRECT",
                ]
            }
        }
        self.assertEqual(
            bootstrap_nameservers(model),
            ["114.114.114.114", "223.5.5.5", "1.12.12.12"],
        )
        with self.assertRaises(BuildError):
            bootstrap_nameservers(
                {"dns": {"default-nameserver": ["1.1.1.1#Proxy"]}}
            )

    def test_dns_forward_preserves_cn_policy_and_direct_domain_rules(self):
        model = {
            "dns": {"nameserver-policy": {"rule-set:cn": ["system"]}},
            "rules": [
                "RULE-SET,private,Direct",
                "RULE-SET,cn_ip,Direct",
                "RULE-SET,google,Proxy",
                "DOMAIN-SUFFIX,internal.example,Direct",
                "MATCH,Final",
            ],
        }
        providers = {
            "cn": {"behavior": "domain"},
            "private": {"behavior": "domain"},
            "cn_ip": {"behavior": "ipcidr"},
            "google": {"behavior": "domain"},
        }
        files = {
            "cn": "cn.yaml",
            "private": "private.yaml",
            "cn_ip": "cn-ip.yaml",
            "google": "google.yaml",
        }
        forward = render_dns_forward(model, providers, files)
        self.assertEqual(
            forward,
            [
                {
                    "proxy_rule_set": {
                        "match": "https://raw.githubusercontent.com/frostmage1250/egern-config/main/rules/apns.yaml",
                        "value": "Foreign",
                        "update_interval": 86400,
                    }
                },
                {
                    "proxy_rule_set": {
                        "match": "https://raw.githubusercontent.com/frostmage1250/egern-config/main/rules/cn.yaml",
                        "value": "system",
                        "update_interval": 86400,
                    }
                },
                {
                    "proxy_rule_set": {
                        "match": "https://raw.githubusercontent.com/frostmage1250/egern-config/main/rules/private.yaml",
                        "value": "system",
                        "update_interval": 86400,
                    }
                },
                {
                    "domain_suffix": {
                        "match": "internal.example",
                        "value": "system",
                    }
                },
                {"domain_wildcard": {"match": "*", "value": "Foreign"}},
            ],
        )

    def test_dns_policy_provider_is_generated_even_when_not_in_routing_rules(self):
        model = {
            "dns": {"nameserver-policy": {"rule-set:cn": ["system"]}},
            "rules": ["RULE-SET,google,Proxy", "MATCH,Final"],
        }
        self.assertEqual(referenced_providers(model), ["google", "cn"])


if __name__ == "__main__":
    unittest.main()
