from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from build_egern import (  # noqa: E402
    parse_domain_list,
    parse_ip_list,
    real_ip_domains,
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

    def test_real_ip_domains_merge_sets_without_disabling_fake_ip(self):
        result = real_ip_domains([
            {"domain_set": ["private.local"]},
            {"domain_wildcard_set": ["*", "*.lan"]},
            {"domain_suffix_set": ["example.cn"]},
        ])
        self.assertNotIn("*", result)
        self.assertIn("private.local", result)
        self.assertIn("*.lan", result)
        self.assertIn("example.cn", result)
        self.assertIn("*.example.cn", result)

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
        self.assertEqual(list(rules[0]), ["domain_suffix"])
        self.assertEqual(rules[1]["rule_set"]["policy"], "Proxy")
        self.assertTrue(rules[2]["rule_set"]["no_resolve"])
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
        self.assertIn("traffic", filters["订阅"])


if __name__ == "__main__":
    unittest.main()
