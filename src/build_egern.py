#!/usr/bin/env python3
"""Generate an Egern profile and native YAML rule sets from the current Mihomo script."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import sys
import urllib.request
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
RULE_DIR = ROOT / "rules"
PROFILE_PATH = ROOT / "Profile.yaml"
REPORT_PATH = ROOT / "reports" / "source.json"
RAW_BASE = "https://raw.githubusercontent.com/frostmage1250/egern-config/main"
MIHOMO_REPO = "frostmage1250/mihomo-script"
BETT_REPO = "appshubcc/bett-rules"
FLOWER_HOSTS = {
    "11612bj3-b76c.aws-agent.biz": "06996bj6-79x5.apt-agent.com",
    "b76c5sh0-fde6.aws-agent.biz": "08233sh6-12d1.apt-agent.com",
    "fde63gz6-1y61.aws-agent.biz": "09571gz6-86k1.apt-agent.com",
}
MESL_PROXY_DNS = [
    "https://zone.rlose.com:39933/api-query",
    "https://radar.rlose.com/api-query",
]
BUILTIN_POLICIES = {"DIRECT", "REJECT"}


class BuildError(RuntimeError):
    pass


def unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def slug(name: str) -> str:
    aliases = {
        "geolocation-!cn": "geolocation-non-cn",
        "private_ip": "private-ip",
        "cn_ip": "cn-ip",
        "google_ip": "google-ip",
        "microsoft_ip": "microsoft-ip",
        "apple_ip": "apple-ip",
        "telegram_ip": "telegram-ip",
        "steam_ip": "steam-ip",
        "tiktok_ip": "tiktok-ip",
        "twitter_ip": "twitter-ip",
        "facebook_ip": "facebook-ip",
        "fakeip_filter": "fakeip-filter",
    }
    value = aliases.get(name, name.replace("_", "-").replace("!", "not-"))
    value = re.sub(r"[^A-Za-z0-9.-]+", "-", value).strip("-").lower()
    if not value:
        raise BuildError(f"Provider name cannot become a file name: {name!r}")
    return value


def source_path(provider: dict[str, Any]) -> str:
    path = provider.get("path-in-bundle")
    if not isinstance(path, str) or not path.endswith(".mrs"):
        url = provider.get("url", "")
        match = re.search(r"/(geo/(?:geosite|geoip)/[^?#]+)\.mrs(?:[?#]|$)", url)
        if not match:
            raise BuildError(f"Cannot derive BettRules source from provider: {provider}")
        path = match.group(1) + ".mrs"
    if not path.startswith(("geo/geosite/", "geo/geoip/")):
        raise BuildError(f"Provider is not backed by BettRules geosite/geoip: {path}")
    return path[:-4] + ".list"


def download_text(url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "egern-config-builder/1"})
    with urllib.request.urlopen(request, timeout=60) as response:
        if getattr(response, "status", 200) != 200:
            raise BuildError(f"HTTP error while fetching {url}")
        return response.read().decode("utf-8-sig")


def parse_domain_list(text: str) -> dict[str, Any]:
    fields: dict[str, list[str]] = {
        "domain_set": [],
        "domain_keyword_set": [],
        "domain_suffix_set": [],
        "domain_regex_set": [],
        "domain_wildcard_set": [],
    }
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";", "//")):
            continue
        if line.startswith("+."):
            fields["domain_suffix_set"].append(line[2:])
        elif line.startswith("full:"):
            fields["domain_set"].append(line[5:])
        elif line.startswith("domain:"):
            fields["domain_suffix_set"].append(line[7:])
        elif line.startswith("keyword:"):
            fields["domain_keyword_set"].append(line[8:])
        elif line.startswith(("regexp:", "regex:")):
            fields["domain_regex_set"].append(line.split(":", 1)[1])
        elif "*" in line or "?" in line:
            fields["domain_wildcard_set"].append(line)
        else:
            fields["domain_set"].append(line)
    result = {key: unique(value) for key, value in fields.items() if value}
    if not result:
        raise BuildError("Domain source produced an empty rule set")
    return result


def parse_ip_list(text: str) -> dict[str, Any]:
    ipv4: list[str] = []
    ipv6: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";", "//")):
            continue
        try:
            network = ipaddress.ip_network(line, strict=False)
        except ValueError as exc:
            raise BuildError(f"Invalid IP network {line!r}") from exc
        target = ipv4 if network.version == 4 else ipv6
        target.append(str(network))
    result: dict[str, Any] = {"no_resolve": True}
    if ipv4:
        result["ip_cidr_set"] = unique(ipv4)
    if ipv6:
        result["ip_cidr6_set"] = unique(ipv6)
    if len(result) == 1:
        raise BuildError("IP source produced an empty rule set")
    return result


def referenced_providers(model: dict[str, Any]) -> list[str]:
    result: list[str] = []
    for rule in model["rules"]:
        parts = rule.split(",")
        if parts[0] == "RULE-SET" and len(parts) >= 3:
            result.append(parts[1])
    if "fakeip_filter" in model["providers"]:
        result.append("fakeip_filter")
    return unique(result)


def regex_text(item: dict[str, str]) -> str:
    return ("(?i)" if "i" in item.get("flags", "") else "") + item["source"]


def negative_filter(patterns: list[str]) -> str:
    bodies = []
    insensitive = False
    for pattern in patterns:
        if pattern.startswith("(?i)"):
            insensitive = True
            pattern = pattern[4:]
        if pattern:
            bodies.append(pattern)
    prefix = "(?i)" if insensitive else ""
    return prefix + "^(?!.*(?:" + "|".join(bodies) + ")).*$"


def render_policy_groups(model: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, str]]:
    regions = {entry["name"]: regex_text(entry) for entry in model["regions"]}
    rates = {entry["name"]: regex_text(entry) for entry in model["rateRegions"]}
    hong_kong = regions.get("香港")
    if not hong_kong:
        raise BuildError("Mihomo region model is missing 香港")

    excluded = [hong_kong]
    if model["options"].get("过滤非地区节点"):
        excluded.append(regex_text(model["excludeFilter"]))
    if model["options"].get("过滤低倍率节点"):
        excluded.extend(rates.values())

    filters: dict[str, str] = {"订阅": negative_filter(excluded)}
    display_name = {"台湾省": "台湾"}
    for source_name, pattern in regions.items():
        if source_name != "香港":
            filters[display_name.get(source_name, source_name)] = pattern
    filters.update(rates)
    filters["其他节点"] = negative_filter(list(regions.values()))

    groups: list[dict[str, Any]] = []
    for source in model["groups"]:
        name = source["name"]
        if name == "订阅":
            groups.append({
                "select": {
                    "name": name,
                    "policies": ["DIRECT"],
                    "urls": [],
                    "filter": filters[name],
                    "update_interval": 86400,
                }
            })
            continue
        if name in filters and name != "订阅":
            groups.append({
                "select": {
                    "name": name,
                    "policies": ["订阅"],
                    "flatten": True,
                    "filter": filters[name],
                }
            })
            continue
        policies = [
            value for value in source.get("proxies", [])
            if not value.startswith("__") and value not in {"IPv4优先", "IPv6优先"}
        ]
        if name == "Direct":
            policies = ["DIRECT"]
        if not policies:
            policies = ["DIRECT"]
        groups.append({"select": {"name": name, "policies": unique(policies)}})
    return groups, filters


def render_rules(
    model: dict[str, Any], provider_files: dict[str, str]
) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    for raw in model["rules"]:
        parts = raw.split(",")
        kind = parts[0]
        if kind == "MATCH" and len(parts) == 2:
            rules.append({"default": {"policy": parts[1]}})
        elif kind == "RULE-SET" and len(parts) >= 3:
            provider = parts[1]
            if provider not in provider_files:
                raise BuildError(f"Rule references missing generated provider: {provider}")
            no_resolve = parts[-1] == "no-resolve"
            policy = parts[-2] if no_resolve else parts[-1]
            item: dict[str, Any] = {
                "match": f"{RAW_BASE}/rules/{provider_files[provider]}",
                "policy": policy,
                "update_interval": 86400,
            }
            if no_resolve:
                item["no_resolve"] = True
            rules.append({"rule_set": item})
        elif kind == "DOMAIN-SUFFIX" and len(parts) == 3:
            rules.append({"domain_suffix": {"match": parts[1], "policy": parts[2]}})
        elif kind == "DOMAIN" and len(parts) == 3:
            rules.append({"domain": {"match": parts[1], "policy": parts[2]}})
        else:
            raise BuildError(f"Unsupported Mihomo rule: {raw}")
    return rules


def real_ip_domains(rule_sets: list[dict[str, Any]]) -> list[str]:
    """Translate Mihomo Fake-IP exclusions without broadening a bare '*' in Egern."""
    result: list[str] = []
    for rule in rule_sets:
        result.extend(rule.get("domain_set", []))
        for value in rule.get("domain_suffix_set", []):
            result.extend([value, f"*.{value}"])
        result.extend(
            value for value in rule.get("domain_wildcard_set", [])
            if value != "*"
        )
    return unique(result)


def nameservers(model: dict[str, Any]) -> list[str]:
    result: list[str] = []
    for value in model.get("dns", {}).get("nameserver", []):
        if not isinstance(value, str):
            continue
        server = value.rsplit("#", 1)[0].strip()
        if server and server not in result:
            result.append(server)
    if not result:
        raise BuildError("Mihomo DNS model contains no nameservers")
    return result


def hosts(model: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for hostname, value in model.get("hosts", {}).items():
        if isinstance(value, list):
            clean = [entry for entry in value if isinstance(entry, str) and entry]
            if clean:
                result[hostname] = clean
        elif isinstance(value, str) and value:
            result[hostname] = value
    result.update(FLOWER_HOSTS)
    return result


def validate_profile(
    profile: dict[str, Any], generated: dict[str, dict[str, Any]]
) -> None:
    groups = [next(iter(item.values())) for item in profile["policy_groups"]]
    names = [item["name"] for item in groups]
    if len(names) != len(set(names)):
        raise BuildError("Policy group names are not unique")
    known = set(names) | BUILTIN_POLICIES
    for group in groups:
        for policy in group.get("policies", []):
            if policy not in known:
                raise BuildError(f"Group {group['name']} references undefined policy {policy}")
    if profile["policy_groups"][names.index("订阅")]["select"].get("urls") != []:
        raise BuildError("Public profile must not contain subscription credentials")
    if profile.get("default_subscription_group") != "订阅":
        raise BuildError("Egern subscriptions must default to the 订阅 group")
    if profile.get("default_proxy_group") != "Proxy":
        raise BuildError("Egern proxies must default to the Proxy group")
    for index, wrapper in enumerate(profile["rules"]):
        kind, value = next(iter(wrapper.items()))
        policy = value["policy"]
        if policy not in known:
            raise BuildError(f"Rule {index} references undefined policy {policy}")
        if kind == "rule_set":
            filename = value["match"].rsplit("/", 1)[-1]
            if filename not in generated:
                raise BuildError(f"Rule references missing YAML file {filename}")
    if list(profile["rules"][-1]) != ["default"]:
        raise BuildError("Default rule must be last")
    dns = profile["dns"]
    if dns.get("proxy_nameservers") != MESL_PROXY_DNS:
        raise BuildError("MESL proxy nameservers were not preserved")
    for hostname, target in FLOWER_HOSTS.items():
        if dns["hosts"].get(hostname) != target:
            raise BuildError(f"Flower host mapping missing: {hostname}")
    if not profile.get("real_ip_domains"):
        raise BuildError("Fake-IP exclusions were not migrated to real_ip_domains")
    if "*" in profile["real_ip_domains"]:
        raise BuildError("Bare '*' would disable Egern Fake-IP globally")


def write_or_check(path: Path, content: str, check: bool) -> bool:
    current = path.read_text(encoding="utf-8") if path.exists() else None
    changed = current != content
    if changed and not check:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")
    return changed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--mihomo-commit", required=True)
    parser.add_argument("--bett-commit", required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    try:
        model = json.loads(args.model.read_text(encoding="utf-8"))
        providers = model["providers"]
        wanted = referenced_providers(model)
        generated: dict[str, dict[str, Any]] = {}
        provider_files: dict[str, str] = {}
        source_records: list[dict[str, Any]] = []

        for name in wanted:
            provider = providers.get(name)
            if provider is None:
                raise BuildError(f"Mihomo model is missing provider {name}")
            path = source_path(provider)
            url = f"https://raw.githubusercontent.com/{BETT_REPO}/{args.bett_commit}/{path}"
            source = download_text(url)
            behavior = provider.get("behavior")
            if behavior == "domain":
                rule = parse_domain_list(source)
            elif behavior == "ipcidr":
                rule = parse_ip_list(source)
            else:
                raise BuildError(f"Unsupported provider behavior {behavior!r} for {name}")
            filename = slug(name) + ".yaml"
            provider_files[name] = filename
            generated[filename] = rule
            source_records.append({
                "provider": name,
                "behavior": behavior,
                "source_path": path,
                "source_url": url,
                "output": f"rules/{filename}",
                "entries": sum(len(v) for v in rule.values() if isinstance(v, list)),
                "source_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
            })

        groups, filters = render_policy_groups(model)
        rules = render_rules(model, provider_files)
        fakeip_name = provider_files.get("fakeip_filter")
        if not fakeip_name:
            raise BuildError("Mihomo fakeip_filter provider is required")

        profile = {
            "auto_update": {"url": f"{RAW_BASE}/Profile.yaml", "interval": 86400},
            "ipv6": True,
            "hijack_dns": ["*:53"],
            "block_quic": False,
            "close_connections_on_policy_change": True,
            "default_subscription_group": "订阅",
            "default_proxy_group": "Proxy",
            "real_ip_domains": real_ip_domains([
                generated[provider_files["private"]],
                generated[fakeip_name],
                generated[provider_files["geolocation-cn"]],
            ]),
            "dns": {
                "bootstrap": ["system"],
                "upstreams": {"Foreign": nameservers(model)},
                "forward": [
                    {
                        "proxy_rule_set": {
                            "match": f"{RAW_BASE}/rules/{provider_files['geolocation-cn']}",
                            "value": "system",
                            "update_interval": 86400,
                        }
                    },
                    {"domain_wildcard": {"match": "*", "value": "Foreign"}},
                ],
                "hosts": hosts(model),
                "proxy_nameservers": MESL_PROXY_DNS,
            },
            "policy_groups": groups,
            "rules": rules,
        }
        validate_profile(profile, generated)

        yaml_options = dict(allow_unicode=True, sort_keys=False, width=1000)
        profile_text = yaml.safe_dump(profile, **yaml_options)
        output_texts = {
            filename: yaml.safe_dump(content, **yaml_options)
            for filename, content in generated.items()
        }

        expected = set(output_texts)
        stale = (
            {path.name for path in RULE_DIR.glob("*.yaml")} - expected
            if RULE_DIR.exists() else set()
        )
        changed: list[str] = []
        if write_or_check(PROFILE_PATH, profile_text, args.check):
            changed.append("Profile.yaml")
        for filename, content in output_texts.items():
            if write_or_check(RULE_DIR / filename, content, args.check):
                changed.append(f"rules/{filename}")
        if stale:
            if args.check:
                changed.extend(f"rules/{name}" for name in sorted(stale))
            else:
                for name in stale:
                    (RULE_DIR / name).unlink()

        report_data = {
            "schema_version": 1,
            "mihomo_script": {
                "repository": MIHOMO_REPO,
                "commit": args.mihomo_commit,
            },
            "bett_rules": {
                "repository": BETT_REPO,
                "branch": "meta",
                "commit": args.bett_commit,
            },
            "profile_sha256": hashlib.sha256(profile_text.encode("utf-8")).hexdigest(),
            "policy_groups": len(groups),
            "routing_rules": len(rules),
            "real_ip_domains": len(profile["real_ip_domains"]),
            "native_rule_sets": source_records,
            "group_filters": filters,
            "subscription": {
                "group": "订阅",
                "default_proxy_group": "Proxy",
                "urls_published": False,
                "reason": "Subscription credentials must not be committed to a public repository.",
            },
            "migration_boundaries": [
                "Mihomo IPv4/IPv6 preferred DIRECT pseudo-proxies map to Egern DIRECT.",
                "Mihomo private, fakeip_filter, and geolocation-cn are expanded into Egern real_ip_domains.",
                "The bare Mihomo '*' filter is omitted because Egern would interpret it as all domains and disable Fake-IP globally.",
                "BettRules text sources are converted directly to Egern native YAML; MRS is not converted.",
            ],
        }
        report_text = json.dumps(report_data, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        if write_or_check(REPORT_PATH, report_text, args.check):
            changed.append("reports/source.json")

        if args.check and changed:
            raise BuildError("Generated files are out of date: " + ", ".join(changed))
        print(
            f"Generated {len(groups)} policy groups, {len(rules)} routing rules, "
            f"{len(generated)} native Egern rule sets, and "
            f"{len(profile['real_ip_domains'])} real-IP domains."
        )
        return 0
    except (BuildError, OSError, ValueError, KeyError, json.JSONDecodeError, yaml.YAMLError) as exc:
        print(f"Build failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
