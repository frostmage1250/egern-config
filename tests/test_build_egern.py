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
    render_policy_groups,
    render_rules,
    validate_rule_alignment,
)


class EgernProfileBuilderTests(unittest.TestCase):
    def test_standalone_privaterelay_is_retained_before_apple(self):
        model = {"rules": [
            "RULE-SET,apple_cn,Direct", "RULE-SET,apple,Proxy",
            "RULE-SET,apple_ip,Proxy,no-resolve", "MATCH,Final",
        ]}
        files = {
            "apple_cn": ["apple-cn.yaml"], "apple": ["apple-merged.yaml"],
            "apple_ip": ["apple-ip.yaml"], "privaterelay": ["privaterelay.yaml"],
        }
        rules = render_rules(model, files)
        self.assertEqual(len(rules), len(model["rules"]) + 2)
        self.assertEqual(rules[2], {"rule_set": {
            "match": f"{RAW_BASE}/dist/egern/privaterelay.yaml",
            "policy": "Proxy", "name": "privaterelay", "update_interval": 86400,
        }})
        self.assertTrue(rules[3]["rule_set"]["match"].endswith("/apple-merged.yaml"))
        validate_rule_alignment(rules, model, files)
        for mutation in ("missing", "duplicate", "position", "policy"):
            with self.subTest(mutation=mutation):
                changed = json.loads(json.dumps(rules))
                if mutation == "missing":
                    changed.pop(2)
                elif mutation == "duplicate":
                    changed.insert(2, changed[2])
                elif mutation == "position":
                    changed[1], changed[2] = changed[2], changed[1]
                else:
                    changed[2]["rule_set"]["policy"] = "Direct"
                with self.assertRaises(BuildError):
                    validate_rule_alignment(changed, model, files)

    def test_apple_merge_keeps_cn_priority_and_separate_ip_rule(self):
        model = {"rules": [
            "RULE-SET,apple_cn,Direct",
            "RULE-SET,apple,Proxy",
            "RULE-SET,apple_ip,Proxy,no-resolve",
            "MATCH,Final",
        ]}
        rules = render_rules(model, {
            "apple_cn": ["apple-cn.yaml"],
            "apple": ["apple-merged.yaml"],
            "apple_ip": ["apple-ip.yaml"],
        })
        selected = [rule["rule_set"] for rule in rules if (
            "rule_set" in rule and rule["rule_set"]["match"].rsplit("/", 1)[-1]
            in {"apple-cn.yaml", "apple-merged.yaml", "apple-ip.yaml"}
        )]
        self.assertEqual(
            [(rule["match"].rsplit("/", 1)[-1], rule["policy"]) for rule in selected],
            [("apple-cn.yaml", "Direct"), ("apple-merged.yaml", "Proxy"), ("apple-ip.yaml", "Proxy")],
        )
        self.assertTrue(selected[2]["no_resolve"])

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
        model = {"rules": [
            "DOMAIN-SUFFIX,example.com,Direct",
            "RULE-SET,domain,Proxy", "RULE-SET,ip,Direct,no-resolve", "MATCH,Final",
        ]}
        files = {"domain": ["domain.yaml"], "ip": ["ip.yaml"]}
        rules = render_rules(model, files)
        self.assertEqual(rules, [
            {"rule_set": {"match": f"{RAW_BASE}/dist/egern/apns.yaml",
                          "policy": "Proxy", "update_interval": 86400, "no_resolve": True}},
            {"domain_suffix": {"match": "example.com", "policy": "Direct"}},
            {"rule_set": {"match": f"{RAW_BASE}/dist/egern/domain.yaml",
                          "policy": "Proxy", "update_interval": 86400}},
            {"rule_set": {"match": f"{RAW_BASE}/dist/egern/ip.yaml",
                          "policy": "Direct", "update_interval": 86400, "no_resolve": True}},
            {"default": {"policy": "Final"}},
        ])
        validate_rule_alignment(rules, model, files)

    def test_private_and_mcdn_stay_at_the_source_position(self):
        model = {"rules": [
            "RULE-SET,claude,Claude", "DOMAIN,cdn.jsdmirror.com,Direct",
            "RULE-SET,private,Direct", "RULE-SET,private_ip,Direct,no-resolve",
            "RULE-SET,mcdn屏蔽,REJECT", "RULE-SET,cn,Direct", "MATCH,Final",
        ]}
        files = {name: [filename] for name, filename in (
            ("claude", "claude.yaml"), ("private", "private.yaml"),
            ("private_ip", "private-ip.yaml"), ("mcdn屏蔽", "mcdn-block.yaml"),
            ("cn", "cn.yaml"),
        )}
        rules = render_rules(model, files)
        self.assertTrue(rules[1]["rule_set"]["match"].endswith("/claude.yaml"))
        self.assertEqual(rules[2], {"domain": {"match": "cdn.jsdmirror.com", "policy": "Direct"}})
        self.assertTrue(rules[3]["rule_set"]["match"].endswith("/private.yaml"))
        self.assertTrue(rules[4]["rule_set"]["no_resolve"])
        self.assertEqual(rules[5]["rule_set"]["policy"], "REJECT")
        self.assertEqual(len(rules), len(model["rules"]) + 1)
        validate_rule_alignment(rules, model, files)

    def test_service_rule_policies_are_not_overridden(self):
        model = {"rules": [
            "RULE-SET,youtube,媒体", "RULE-SET,appletv,Proxy",
            "RULE-SET,porn,pron", "MATCH,Final",
        ]}
        files = {name: [name + ".yaml"] for name in ("youtube", "appletv", "porn")}
        rules = render_rules(model, files)
        self.assertEqual(
            [rule["rule_set"]["policy"] for rule in rules[1:-1]],
            ["媒体", "Proxy", "porn"],
        )
        validate_rule_alignment(rules, model, files)

    def test_future_source_order_and_duplicates_are_preserved(self):
        source = [
            "RULE-SET,pikpak,PikPak", "RULE-SET,github,GitHub",
            "RULE-SET,steam,Proxy", "RULE-SET,steam_ip,Proxy,no-resolve",
            "RULE-SET,ai,AI", "RULE-SET,claude,Claude",
            "RULE-SET,private,Direct", "RULE-SET,private,Direct", "MATCH,Final",
        ]
        files = {name: [name + ".yaml"] for name in
                 ("pikpak", "github", "steam", "steam_ip", "ai", "claude", "private")}
        rules = render_rules({"rules": source}, files)
        self.assertEqual(
            [rule["rule_set"]["match"].rsplit("/", 1)[-1][:-5] for rule in rules[1:-1]],
            ["pikpak", "github", "steam", "steam_ip", "ai", "claude", "private", "private"],
        )
        self.assertEqual(len(rules), len(source) + 1)
        validate_rule_alignment(rules, {"rules": source}, files)

    def test_porn_alias_updates_the_target_and_alignment_check(self):
        model = {"rules": [
            "RULE-SET,porn,pron", "RULE-SET,geolocation-!cn,Proxy", "MATCH,Final",
        ]}
        files = {"porn": ["porn.yaml"], "geolocation-!cn": ["geolocation-non-cn.yaml"]}
        rules = render_rules(model, files)
        self.assertEqual(rules[1]["rule_set"]["policy"], "porn")
        self.assertEqual(rules[2]["rule_set"]["policy"], "Proxy")
        validate_rule_alignment(rules, model, files)
        rules[1]["rule_set"]["policy"] = "pron"
        with self.assertRaises(BuildError):
            validate_rule_alignment(rules, model, files)

    def test_alignment_rejects_reorder_extra_missing_policy_and_flag_changes(self):
        model = {"rules": [
            "RULE-SET,service,Proxy", "RULE-SET,service_ip,Proxy,no-resolve",
            "DOMAIN,example.com,Direct", "MATCH,Final",
        ]}
        files = {"apns": ["apns.yaml"], "service": ["service.yaml"], "service_ip": ["service-ip.yaml"]}
        original = render_rules(model, files)
        for change in ("reorder", "extra", "missing", "policy", "flag", "apns"):
            with self.subTest(change=change):
                rules = json.loads(json.dumps(original))
                if change == "reorder":
                    rules[1], rules[2] = rules[2], rules[1]
                elif change == "extra":
                    rules.insert(2, rules[1])
                elif change == "missing":
                    rules.pop(1)
                elif change == "policy":
                    rules[1]["rule_set"]["policy"] = "Direct"
                elif change == "flag":
                    del rules[2]["rule_set"]["no_resolve"]
                else:
                    rules[0]["rule_set"]["policy"] = "Direct"
                with self.assertRaises(BuildError):
                    validate_rule_alignment(rules, model, files)

    def test_dns_never_injects_additional_routing_rules(self):
        model = {"dns": {"nameserver": [
            "https://cloudflare-dns.com/dns-query#Proxy",
            "https://dns.google/dns-query#Proxy",
        ]}, "rules": ["MATCH,Final"]}
        self.assertEqual(nameservers(model), [
            "https://cloudflare-dns.com/dns-query", "https://dns.google/dns-query",
        ])
        self.assertEqual(render_dns_upstreams(model)["Foreign"], nameservers(model))
        rules = render_rules(model, {})
        self.assertEqual(len(rules), 2)
        validate_rule_alignment(rules, model, {})
        for endpoint in ("1.1.1.1#DIRECT", "https://dns.example/dns-query#Proxy"):
            with self.subTest(endpoint=endpoint), self.assertRaises(BuildError):
                nameservers({"dns": {"nameserver": [endpoint]}})

    def test_nameserver_policy_suffix_cannot_be_silently_dropped(self):
        for endpoint in (
            "https://dns.example/dns-query#",
            "https://dns.example/dns-query#DIRECT",
            "https://dns.google/dns-query#DIRECT",
        ):
            with self.subTest(endpoint=endpoint), self.assertRaises(BuildError):
                nameservers({"dns": {"nameserver": [endpoint]}})

    def test_groups_keep_subscription_private_and_region_filters_dynamic(self):
        model = {
            "regions": [
                {"name": "香港", "source": "HK|香港", "flags": "i"},
                {"name": "新加坡", "source": "SG|新加坡", "flags": "i"},
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
                {"name": "新加坡", "proxies": ["__新加坡__"]},
                {"name": "其他节点", "proxies": ["__其他节点__"]},
                {"name": "低倍率节点", "proxies": ["__低倍率节点__"]},
                {"name": "Telegram", "proxies": ["Proxy", "低倍率节点"]},
                {"name": "媒体", "proxies": ["Proxy", "低倍率节点"]},
                {"name": "YouTube", "proxies": ["Proxy", "香港", "低倍率节点"]},
                {"name": "PikPak", "proxies": ["Proxy", "Direct", "低倍率节点"]},
                {"name": "pron", "proxies": []},
                {"name": "Final", "proxies": ["Proxy", "Direct", "pron"]},
            ],
        }
        groups, filters = render_policy_groups(model)
        by_name = {
            next(iter(item.values()))["name"]: next(iter(item.values()))
            for item in groups
        }
        self.assertEqual(
            by_name["Proxy"],
            {"name": "Proxy", "policies": ["订阅", "订阅2", "日本"], "flatten": True},
        )
        self.assertFalse(by_name["AI"].get("flatten", False))
        self.assertFalse(by_name["Claude"].get("flatten", False))
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
        self.assertEqual(by_name["porn"]["policies"], ["香港", "新加坡"])
        self.assertFalse(by_name["porn"].get("flatten", False))
        self.assertNotIn("pron", by_name)
        self.assertEqual(by_name["Final"]["policies"], ["Proxy", "Direct", "porn"])
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

    def test_bootstrap_tracks_mihomo_additions_and_removals(self):
        model = {"dns": {"default-nameserver": ["119.29.29.29#DIRECT", "223.5.5.5"]}}
        self.assertEqual(bootstrap_nameservers(model), ["119.29.29.29", "223.5.5.5"])
        model["dns"]["default-nameserver"].append("https://9.9.9.9/dns-query#DIRECT")
        self.assertEqual(
            bootstrap_nameservers(model),
            ["119.29.29.29", "223.5.5.5", "9.9.9.9"],
        )
        model["dns"]["default-nameserver"].pop(0)
        self.assertEqual(bootstrap_nameservers(model), ["223.5.5.5", "9.9.9.9"])

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

    def test_dns_policy_prevents_only_redundant_synthesized_forwarding(self):
        model = {
            "dns": {"nameserver-policy": {
                "rule-set:private": "system",
                "rule-set:custom": ["system", "180.184.1.1"],
            }},
            "rules": [
                "RULE-SET,private,Direct", "RULE-SET,private,Direct",
                "RULE-SET,custom,Direct",
                "DOMAIN-SUFFIX,internal.example,Direct",
                "DOMAIN-SUFFIX,internal.example,Direct", "MATCH,Final",
            ],
        }
        providers = {name: {"behavior": "domain"} for name in ("private", "custom")}
        files = {name: [name + ".yaml"] for name in providers}
        forward = render_dns_forward(model, providers, files)
        matches = [next(iter(item.values()))["match"] for item in forward]
        self.assertEqual(matches.count(f"{RAW_BASE}/dist/egern/private.yaml"), 1)
        self.assertEqual(matches.count(f"{RAW_BASE}/dist/egern/custom.yaml"), 1)
        self.assertEqual(matches.count("internal.example"), 2)
        self.assertEqual(forward[2]["proxy_rule_set"]["value"], "Policy-custom")
        self.assertEqual(len(render_rules(model, files)), len(model["rules"]) + 1)

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
                    "https://cloudflare-dns.com/dns-query#Proxy",
                    "https://cloudflare-dns.com/dns-query#Proxy",
                ],
            },
            "rules": [
                "DOMAIN-SUFFIX,internal.example,Direct",
                "DOMAIN-SUFFIX,internal.example,Direct",
                "MATCH,Final",
            ],
        }
        self.assertEqual(len(nameservers(model)), 2)
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

    def test_manifest_loads_and_verifies_standalone_privaterelay(self):
        texts = {
            "apns.yaml": "domain_set:\n- push.apple.com\n",
            "privaterelay.yaml": "domain_suffix_set:\n- mask.icloud.com\n",
        }
        def record(provider, filename, sequence):
            digest = hashlib.sha256(
                json.dumps(sequence, ensure_ascii=False, separators=(",", ":")).encode()
            ).hexdigest()
            return {
                "provider": provider, "behavior": "domain", "source_entries": 1, "entries": 1,
                "source_order_sha256": digest, "native_entries_sha256": digest,
                "output": "dist/egern/" + filename,
                "output_sha256": hashlib.sha256(texts[filename].encode()).hexdigest(),
            }
        apns = record("apns", "apns.yaml", [("domain_set", "push.apple.com")])
        apns.update({"source_repository": "ttyyss2233/Tool", "source_path": "shadowrocket/rules/apns.list"})
        private = record("privaterelay", "privaterelay.yaml", [("domain_suffix_set", "mask.icloud.com")])
        private["egern_only"] = True
        manifest = {
            "schema_version": 3, "mihomo_script": {"repository": "frostmage1250/mihomo-script"},
            "native_rule_sets": [apns], "egern_only_rule_sets": [private],
        }
        with patch("build_egern.download_text", side_effect=lambda url: texts[url.rsplit("/", 1)[-1]]) as download:
            generated, files = load_manifest_rules(
                {"providers": {}, "rules": ["MATCH,Final"]}, manifest, "converter-commit"
            )
            self.assertEqual(list(files), ["apns", "privaterelay"])
            self.assertEqual(generated["privaterelay.yaml"]["domain_suffix_set"], ["mask.icloud.com"])
            self.assertEqual(download.call_count, 2)
            private["output_sha256"] = "0" * 64
            with self.assertRaises(BuildError):
                load_manifest_rules({"providers": {}, "rules": ["MATCH,Final"]}, manifest, "converter-commit")

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
