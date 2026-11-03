import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import build_egern as builder


class EgernAdaptationTests(unittest.TestCase):
    def test_mcdn_and_private_relay_placements_preserve_source_and_dns(self):
        quic = "AND,((NETWORK,UDP),(DST-PORT,443)),REJECT"
        source = [
            "DOMAIN,first.example,Direct", "RULE-SET,private,Direct",
            "RULE-SET,geolocation-cn,Direct", quic, "RULE-SET,mcdn屏蔽,REJECT",
            "RULE-SET,microsoft,Proxy", "RULE-SET,appletv,媒体",
            "RULE-SET,apple_podcasts,媒体", "RULE-SET,apple,Proxy",
            "RULE-SET,cn_ip,Direct,no-resolve", "MATCH,Final",
        ]
        model = {"rules": source, "quic_rules": [quic], "dns": {}}
        files = {name: [file] for name, file in [
            ("private", "private.yaml"), ("geolocation-cn", "geolocation-cn.yaml"),
            ("mcdn屏蔽", "mcdn-block.yaml"), ("apns", "apns.yaml"),
            ("microsoft", "microsoft.yaml"), ("appletv", "appletv.yaml"),
            ("apple_podcasts", "apple-podcasts.yaml"),
            ("apple", "apple.yaml"), ("privaterelay", "privaterelay.yaml"), ("cn_ip", "cn-ip.yaml"),
        ]}
        rules = builder.render_rules(model, files)
        self.assertEqual([next(iter(item)) for item in rules],
                         ["domain"] + ["rule_set"] * 10 + ["default"])
        values = [next(iter(item.values())) for item in rules]
        self.assertEqual(values[0]["policy"], "DIRECT")
        self.assertTrue(values[-2]["no_resolve"])
        self.assertEqual([value["match"].rsplit("/", 1)[-1] for value in values[1:-1]],
                         ["private.yaml", "mcdn-block.yaml", "geolocation-cn.yaml",
                          "apns.yaml", "microsoft.yaml", "privaterelay.yaml", "appletv.yaml",
                          "apple-podcasts.yaml", "apple.yaml", "cn-ip.yaml"])
        self.assertEqual(values[2]["policy"], "REJECT")
        self.assertEqual(model["rules"], source)
        self.assertEqual(model["rules"][2], "RULE-SET,geolocation-cn,Direct")
        self.assertEqual(model["rules"][4], "RULE-SET,mcdn屏蔽,REJECT")
        self.assertIn(quic, model["rules"])

    def test_subscriptions_start_empty_and_filtered_groups_use_both(self):
        names = ["Proxy", "订阅", "Direct", "香港", "日本", "美国", "新加坡", "低倍率节点", "媒体", "porn"]
        model = {
            "groups": [{"name": name, "proxies": ["Direct", "IPv4优先"] if name == "Proxy" else ["Proxy"]}
                       for name in names],
            "regions": [{"name": name, "source": name, "flags": "i"} for name in ["香港", "日本", "美国", "新加坡"]],
            "rateRegions": [{"name": "低倍率节点", "source": "低倍", "flags": "i"}],
            "homeRegions": [], "options": {}, "excludeFilter": {"source": "流量", "flags": "i"},
        }
        groups = {item["select"]["name"]: item["select"] for item in builder.render_policy_groups(model)}
        self.assertNotIn("Direct", groups)
        for name in ["订阅", "订阅2"]:
            self.assertEqual(groups[name]["policies"], [])
            self.assertEqual(groups[name]["urls"], [])
            self.assertNotIn("update_interval", groups[name])
        self.assertEqual(groups["香港"]["policies"], ["订阅", "订阅2"])
        self.assertTrue(groups["香港"]["flatten"])
        self.assertEqual(groups["Proxy"]["policies"], ["订阅", "订阅2", "DIRECT"])
        self.assertIn("实验", groups["低倍率节点"]["filter"])
        self.assertIn("美国", groups["媒体"]["policies"])

    def test_fixed_direct_dns_precedes_shared_policy(self):
        model = {
            "rules": ["DOMAIN,first.example,Direct", "RULE-SET,direct,Direct", "RULE-SET,service,Proxy", "MATCH,Final"],
            "providers": {"direct": {"behavior": "domain"}, "cn": {"behavior": "domain"}},
            "dns": {"nameserver": ["https://dns.google/dns-query#Proxy"],
                    "nameserver-policy": {"rule-set:cn": ["system"]}},
        }
        forward = builder.render_dns_forward(model, model["providers"], {"direct": ["direct.yaml"], "cn": ["cn.yaml"]})
        self.assertEqual(forward[0], {"domain": {"match": "first.example", "value": "system"}})
        self.assertTrue(forward[1]["proxy_rule_set"]["match"].endswith("/direct.yaml"))
        self.assertTrue(forward[2]["proxy_rule_set"]["match"].endswith("/cn.yaml"))
        self.assertEqual(forward[-1]["domain_wildcard"]["value"], "Foreign")
        self.assertEqual(builder.nameservers(model), ["https://dns.google/dns-query"])


if __name__ == "__main__":
    unittest.main()
