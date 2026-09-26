from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from build_egern import (  # noqa: E402
    BuildError,
    bootstrap_nameservers,
    load_manifest_rules,
    nameservers,
    referenced_providers,
    render_dns_forward,
    render_dns_upstreams,
    render_nameserver_route_rules,
    render_policy_groups,
    render_rules,
    validate_business_ip_pairs,
)


class EgernProfileBuilderTests(unittest.TestCase):
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
            rules[0],
            {"protocol": {"match": "stun", "policy": "REJECT"}},
        )
        self.assertEqual(
            rules[1]["rule_set"]["match"],
            "https://raw.githubusercontent.com/frostmage1250/proxy-rules-converter/main/dist/egern/apns.yaml",
        )
        self.assertEqual(rules[1]["rule_set"]["policy"], "Proxy")
        self.assertTrue(rules[1]["rule_set"]["no_resolve"])
        self.assertEqual(list(rules[2]), ["domain_suffix"])
        self.assertEqual(rules[3]["rule_set"]["policy"], "Proxy")
        self.assertTrue(rules[4]["rule_set"]["no_resolve"])
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
        self.assertEqual(render_rules(model, {})[2:5], expected)

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
                        "match": "https://raw.githubusercontent.com/frostmage1250/proxy-rules-converter/main/dist/egern/apns.yaml",
                        "value": "Foreign",
                        "update_interval": 86400,
                    }
                },
                {
                    "proxy_rule_set": {
                        "match": "https://raw.githubusercontent.com/frostmage1250/proxy-rules-converter/main/dist/egern/cn.yaml",
                        "value": "system",
                        "update_interval": 86400,
                    }
                },
                {
                    "proxy_rule_set": {
                        "match": "https://raw.githubusercontent.com/frostmage1250/proxy-rules-converter/main/dist/egern/private.yaml",
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

    def test_dns_policy_preserves_system_and_explicit_servers(self):
        model = {
            "dns": {
                "nameserver": ["https://dns.google/dns-query#Proxy"],
                "nameserver-policy": {
                    "rule-set:douyin": ["system", "180.184.1.1", "180.184.2.2"]
                },
            },
            "rules": [],
        }
        self.assertEqual(
            render_dns_upstreams(model)["Policy-douyin"],
            ["system", "180.184.1.1", "180.184.2.2"],
        )
        forward = render_dns_forward(
            model, {"douyin": {"behavior": "domain"}}, {"douyin": "douyin.yaml"}
        )
        self.assertEqual(forward[1]["proxy_rule_set"]["value"], "Policy-douyin")

    def test_dns_policy_provider_is_generated_even_when_not_in_routing_rules(self):
        model = {
            "dns": {"nameserver-policy": {"rule-set:cn": ["system"]}},
            "rules": ["RULE-SET,google,Proxy", "MATCH,Final"],
        }
        self.assertEqual(referenced_providers(model), ["google", "cn"])

    def test_manifest_must_cover_all_referenced_providers(self):
        model = {
            "providers": {"service": {"behavior": "domain"}},
            "rules": ["RULE-SET,service,Proxy", "MATCH,Final"],
        }
        manifest = {
            "schema_version": 1,
            "mihomo_script": {"repository": "frostmage1250/mihomo-script"},
            "native_rule_sets": [],
        }
        with self.assertRaises(BuildError):
            load_manifest_rules(model, manifest, "converter-commit")


if __name__ == "__main__":
    unittest.main()
