from __future__ import annotations

import hashlib
import json
import re
import sys
import unittest
from unittest.mock import patch
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from build_egern import (  # noqa: E402
    BuildError,
    RAW_BASE,
    bootstrap_nameservers,
    hosts,
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
    def test_hosts_preserve_source_without_injecting_pcdn_blocks(self):
        source_hosts = {
            "example.com": ["203.0.113.13"],
            "alias.example.com": "target.example.com",
            "dns.alidns.com": ["223.5.5.5"],
        }
        source_snapshot = json.dumps(source_hosts, sort_keys=True)
        rendered = hosts({"hosts": source_hosts})
        for domain in ("mcdn.bilivideo.com", "mcdn.bilivideo.cn",
                       "edge.mountaintoys.cn", "h2.smtcdns.net"):
            self.assertNotIn(domain, rendered)
            self.assertNotIn(f"*.{domain}", rendered)
        self.assertEqual(rendered["example.com"], ["203.0.113.13"])
        self.assertEqual(rendered["alias.example.com"], "target.example.com")
        self.assertEqual(rendered["dns.alidns.com"], ["223.5.5.5", "223.6.6.6"])
        self.assertEqual(
            rendered["11612bj3-b76c.aws-agent.biz"],
            "06996bj6-79x5.apt-agent.com",
        )
        self.assertEqual(json.dumps(source_hosts, sort_keys=True), source_snapshot)

    def test_rules_preserve_order_and_no_resolve(self):
        model = {
            "rules": [
                "DOMAIN-SUFFIX,example.com,Direct",
                "RULE-SET,domain,Proxy",
                "RULE-SET,ip,Direct,no-resolve",
                "MATCH,Final",
            ]
        }
        rules = render_rules(model, {"domain": ["domain.yaml"], "ip": ["ip.yaml"]})
        self.assertTrue(rules[0]["rule_set"]["match"].endswith("/apns.yaml"))
        self.assertEqual(rules[0]["rule_set"]["policy"], "Proxy")
        self.assertTrue(rules[0]["rule_set"]["no_resolve"])
        self.assertEqual(rules[1], {"protocol": {"match": "stun", "policy": "REJECT"}})
        self.assertEqual(list(rules[3]), ["domain_suffix"])
        self.assertTrue(rules[4]["rule_set"]["match"].endswith("/domain.yaml"))
        self.assertEqual(rules[4]["rule_set"]["policy"], "Proxy")
        self.assertTrue(rules[5]["rule_set"]["match"].endswith("/ip.yaml"))
        self.assertTrue(rules[5]["rule_set"]["no_resolve"])
        self.assertEqual(list(rules[-1]), ["default"])

    def test_mcdn_set_follows_stun_once_and_precedes_mainland_direct_rules(self):
        model = {
            "rules": [
                "RULE-SET,mcdn屏蔽,REJECT",
                "DOMAIN-SUFFIX,bilivideo.com,Direct",
                "DOMAIN-SUFFIX,bilivideo.cn,Direct",
                "RULE-SET,cn,Direct",
                "MATCH,Final",
            ]
        }
        rules = render_rules(model, {
            "mcdn屏蔽": ["mcdn-block.yaml"], "cn": ["cn.yaml"]
        })
        self.assertEqual(rules[1], {"protocol": {"match": "stun", "policy": "REJECT"}})
        self.assertEqual(rules[2], {"rule_set": {
            "match": f"{RAW_BASE}/dist/egern/mcdn-block.yaml",
            "policy": "REJECT", "name": "mcdn屏蔽", "update_interval": 86400,
        }})
        self.assertEqual(
            sum(rule.get("rule_set", {}).get("name") == "mcdn屏蔽" for rule in rules), 1
        )
        self.assertEqual(rules[3], {"domain_suffix": {"match": "bilivideo.com", "policy": "Direct"}})
        self.assertEqual(rules[4], {"domain_suffix": {"match": "bilivideo.cn", "policy": "Direct"}})
        self.assertTrue(rules[5]["rule_set"]["match"].endswith("/cn.yaml"))
        self.assertEqual(rules[-1], {"default": {"policy": "Final"}})

    def test_youtube_rule_uses_its_own_group(self):
        model = {
            "rules": [
                "RULE-SET,youtube,媒体",
                "RULE-SET,meta,媒体",
                "MATCH,Final",
            ]
        }
        rules = render_rules(model, {"youtube": ["youtube.yaml"], "meta": ["meta.yaml"]})
        self.assertEqual(rules[3]["rule_set"]["policy"], "YouTube")
        self.assertEqual(rules[4]["rule_set"]["policy"], "媒体")

    def test_claude_and_ai_rules_precede_github_without_dropping_rules(self):
        model = {
            "rules": [
                "RULE-SET,steam_ip,Proxy,no-resolve",
                "RULE-SET,apple_cn,Direct",
                "RULE-SET,apple,Proxy",
                "RULE-SET,github,GitHub",
                "RULE-SET,claude,Claude",
                "RULE-SET,ai,AI",
                "MATCH,Final",
            ]
        }
        provider_files = {
            name: [name.replace("_", "-") + ".yaml"]
            for name in ("steam_ip", "apple_cn", "apple", "github", "claude", "ai")
        }
        rules = render_rules(model, provider_files)
        ordered = [
            (rule["rule_set"]["match"].rsplit("/", 1)[-1], rule["rule_set"]["policy"])
            for rule in rules
            if "rule_set" in rule and rule["rule_set"].get("name") != "mcdn屏蔽"
            and not rule["rule_set"]["match"].endswith("/apns.yaml")
        ]
        self.assertEqual(
            ordered,
            [
                ("steam-ip.yaml", "Proxy"),
                ("apple-cn.yaml", "Direct"),
                ("apple.yaml", "Proxy"),
                ("claude.yaml", "Claude"),
                ("ai.yaml", "AI"),
                ("github.yaml", "GitHub"),
            ],
        )

    def test_bypass_japan_rule_precedes_foreign_fallback(self):
        model = {
            "rules": [
                "RULE-SET,bypass_japan,绕过日本",
                "RULE-SET,geolocation-!cn,Proxy",
                "MATCH,Final",
            ]
        }
        rules = render_rules(model, {
            "bypass_japan": ["bypass-japan.yaml"],
            "geolocation-!cn": ["geolocation-non-cn.yaml"],
        })
        self.assertEqual(rules[3]["rule_set"]["policy"], "绕过日本")
        self.assertEqual(rules[3]["rule_set"]["match"], f"{RAW_BASE}/dist/egern/bypass-japan.yaml")
        self.assertEqual(rules[4]["rule_set"]["policy"], "Proxy")

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

    def test_two_doh_routes_are_omitted_but_upstreams_remain(self):
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
        self.assertEqual(render_dns_upstreams(model)["Foreign"], nameservers(model))
        self.assertEqual(render_nameserver_route_rules(model), expected)
        self.assertEqual(render_rules(model, {})[3:4], expected)

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
                {"name": "香港", "proxies": ["__香港__"]},
                {"name": "其他节点", "proxies": ["__其他节点__"]},
                {"name": "低倍率节点", "proxies": ["__低倍率节点__"]},
                {"name": "Telegram", "proxies": ["Proxy", "低倍率节点"]},
                {"name": "媒体", "proxies": ["Proxy", "低倍率节点"]},
                {"name": "PikPak", "proxies": ["Proxy", "Direct", "低倍率节点"]},
                {"name": "绕过日本", "proxies": []},
                {"name": "Final", "proxies": ["Proxy", "Direct"]},
            ],
        }
        groups, filters = render_policy_groups(model)
        by_name = {
            next(iter(item.values()))["name"]: next(iter(item.values()))
            for item in groups
        }
        self.assertEqual(by_name["订阅"]["urls"], [])
        self.assertEqual(by_name["订阅2"], {"name": "订阅2", "policies": [], "urls": [], "filter": filters["订阅"]})
        self.assertEqual(by_name["订阅2"]["filter"], by_name["订阅"]["filter"])
        self.assertEqual(
            [next(iter(item.values()))["name"] for item in groups][1:3],
            ["订阅", "订阅2"],
        )
        self.assertEqual(by_name["Direct"]["policies"], ["DIRECT"])
        self.assertEqual(by_name["GitHub"]["policies"], ["Proxy", "订阅", "AI"])
        self.assertEqual(by_name["Claude"]["policies"], ["Proxy", "日本", "其他节点"])
        self.assertEqual(by_name["日本"]["policies"], ["订阅"])
        self.assertTrue(by_name["日本"]["flatten"])
        self.assertEqual(by_name["香港"]["policies"], ["订阅", "订阅2"])
        self.assertTrue(by_name["香港"]["flatten"])
        self.assertIsNotNone(re.search(by_name["香港"]["filter"], "HK Node"))
        self.assertEqual(
            by_name["Telegram"]["policies"], ["Proxy", "低倍率节点", "香港", "订阅", "订阅2"]
        )
        self.assertEqual(
            by_name["媒体"]["policies"], ["Proxy", "低倍率节点", "香港", "订阅", "订阅2"]
        )
        self.assertEqual(by_name["PikPak"]["policies"], ["Proxy", "Direct", "低倍率节点", "香港"])
        self.assertEqual(by_name["YouTube"]["policies"], ["Proxy", "香港", "低倍率节点"])
        self.assertFalse(by_name["YouTube"].get("flatten", False))
        self.assertEqual(by_name["绕过日本"]["policies"], [])
        self.assertEqual(
            [next(iter(item.values()))["name"] for item in groups].index("YouTube"),
            [next(iter(item.values()))["name"] for item in groups].index("媒体") + 1,
        )
        self.assertIn("traffic", filters["订阅"])
        self.assertNotIn("订阅2", filters["订阅"])
        self.assertIsNotNone(re.fullmatch(by_name["订阅2"]["filter"], "HK Node"))
        self.assertIsNone(re.fullmatch(filters["其他节点"], "HK Node"))
        self.assertIsNone(re.fullmatch(by_name["订阅2"]["filter"], "traffic-50GB"))
        self.assertIsNotNone(re.fullmatch(by_name["订阅2"]["filter"], "普通节点"))
        model["options"] = {"过滤非地区节点": False, "过滤低倍率节点": False}
        _, unrestricted_filters = render_policy_groups(model)
        self.assertEqual(unrestricted_filters["订阅"], ".*")

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
            "cn": ["cn.yaml"],
            "private": ["private.yaml"],
            "cn_ip": ["cn-ip.yaml"],
            "google": ["google.yaml"],
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
            model, {"douyin": {"behavior": "domain"}}, {"douyin": ["douyin.yaml"]}
        )
        self.assertEqual(forward[1]["proxy_rule_set"]["value"], "Policy-douyin")

    def test_dns_policy_provider_is_generated_even_when_not_in_routing_rules(self):
        model = {
            "dns": {"nameserver-policy": {"rule-set:cn": ["system"]}},
            "rules": ["RULE-SET,google,Proxy", "MATCH,Final"],
        }
        self.assertEqual(referenced_providers(model), ["google", "cn"])

    def test_repeated_nameserver_and_dns_forward_rules_remain_repeated(self):
        model = {
            "dns": {
                "nameserver": [
                    "https://dns.example/dns-query#Proxy",
                    "https://dns.example/dns-query#Proxy",
                ],
            },
            "rules": [
                "DOMAIN-SUFFIX,internal.example,Direct",
                "DOMAIN-SUFFIX,internal.example,Direct",
                "MATCH,Final",
            ],
        }
        self.assertEqual(len(nameservers(model)), 2)
        self.assertEqual(len(render_nameserver_route_rules(model)), 2)
        forward = render_dns_forward(model, {}, {})
        self.assertEqual(forward[1], forward[2])
        self.assertEqual(len(forward), 4)

    def test_dns_forward_references_one_native_file_per_provider(self):
        model = {
            "dns": {"nameserver-policy": {"rule-set:cn": ["system"]}},
            "rules": ["MATCH,Final"],
        }
        forward = render_dns_forward(
            model, {"cn": {"behavior": "domain"}},
            {"apns": ["apns.yaml"], "cn": ["cn.yaml"]},
        )
        self.assertEqual(
            [item["proxy_rule_set"]["match"].rsplit("/", 1)[-1] for item in forward[:2]],
            ["apns.yaml", "cn.yaml"],
        )

    def test_manifest_verifies_single_native_yaml_count_and_duplicates(self):
        model = {
            "providers": {"service": {"behavior": "domain", "url": "https://example.test/service.mrs"}},
            "rules": ["RULE-SET,service,Proxy", "MATCH,Final"],
        }
        texts = {
            "apns.yaml": "domain_set:\n- push.apple.com\n",
            "service.yaml": (
                "domain_set:\n- a.example\n- a.example\n"
                "domain_suffix_set:\n- example.org\n"
            ),
        }
        def sequence_hash(sequence):
            return hashlib.sha256(
                json.dumps(sequence, ensure_ascii=False, separators=(",", ":")).encode()
            ).hexdigest()
        def record(filename, provider, source_sequence, native_sequence):
            return {
                "provider": provider,
                "source_entries": len(source_sequence),
                "entries": len(source_sequence),
                "source_order_sha256": sequence_hash(source_sequence),
                "native_entries_sha256": sequence_hash(native_sequence),
                "output": "dist/egern/" + filename,
                "output_sha256": hashlib.sha256(texts[filename].encode()).hexdigest(),
            }
        apns = record(
            "apns.yaml", "apns",
            [("domain_set", "push.apple.com")],
            [("domain_set", "push.apple.com")],
        )
        apns.update({
            "source_repository": "ttyyss2233/Tool",
            "source_path": "shadowrocket/rules/apns.list",
        })
        service = record(
            "service.yaml", "service",
            [("domain_set", "a.example"), ("domain_suffix_set", "example.org"),
             ("domain_set", "a.example")],
            [("domain_set", "a.example"), ("domain_set", "a.example"),
             ("domain_suffix_set", "example.org")],
        )
        service.update({
            "provider_url": "https://example.test/service.mrs",
            "behavior": "domain",
        })
        manifest = {
            "schema_version": 3,
            "mihomo_script": {"repository": "frostmage1250/mihomo-script"},
            "native_rule_sets": [apns, service],
        }
        with patch("build_egern.download_text", side_effect=lambda url: texts[url.rsplit("/", 1)[-1]]):
            generated, files = load_manifest_rules(model, manifest, "converter-commit")
            self.assertEqual(files["service"], ["service.yaml"])
            self.assertEqual(generated["service.yaml"]["domain_set"], ["a.example", "a.example"])
            service["native_entries_sha256"] = sequence_hash([("domain_set", "different.example")])
            with self.assertRaises(BuildError):
                load_manifest_rules(model, manifest, "converter-commit")

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
