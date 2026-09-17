from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from build_egern import (  # noqa: E402
    bootstrap_nameservers,
    parse_classical_rule_list,
    parse_domain_list,
    parse_ip_list,
    referenced_providers,
    render_dns_forward,
    render_policy_groups,
    render_rules,
    source_path,
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
        self.assertEqual(result["ip_cidr_set"], ["1.1.1.0/24"])
        self.assertEqual(result["ip_cidr6_set"], ["2001:db8::/32"])

    def test_classical_apns_source_becomes_one_native_mixed_rule_set(self):
        result = parse_classical_rule_list(
            "DOMAIN-SUFFIX,push.apple.com\n"
            "DOMAIN-KEYWORD,apple.com.edgekey.net\n"
            "IP-CIDR,17.249.0.0/16,no-resolve\n"
            "IP-CIDR6,2620:149:a44::/48,no-resolve\n"
        )
        self.assertEqual(result["domain_suffix_set"], ["push.apple.com"])
        self.assertEqual(
            result["domain_keyword_set"], ["apple.com.edgekey.net"]
        )
        self.assertEqual(result["ip_cidr_set"], ["17.249.0.0/16"])
        self.assertEqual(result["ip_cidr6_set"], ["2620:149:a44::/48"])
        self.assertTrue(result["no_resolve"])

    def test_bett_source_comes_from_bundle_path_not_mrs_bytes(self):
        provider = {
            "path-in-bundle": "geo/geosite/google.mrs",
            "url": "https://example.invalid/google.mrs",
        }
        self.assertEqual(source_path(provider), "geo/geosite/google.list")

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
