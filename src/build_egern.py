#!/usr/bin/env python3
"""Generate the Egern profile from a published converter rule manifest."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import sys
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = ROOT / "Profile.yaml"
REPORT_PATH = ROOT / "reports" / "source.json"
RAW_BASE = "https://raw.githubusercontent.com/frostmage1250/proxy-rules-converter/main"
MIHOMO_REPO = "frostmage1250/mihomo-script"
CONVERTER_REPO = "frostmage1250/proxy-rules-converter"
CONVERTER_MANIFEST_PATH = "reports/egern-source.json"
APNS_FILENAME = "apns.yaml"
FLOWER_HOSTS = {
    "11612bj3-b76c.aws-agent.biz": "06996bj6-79x5.apt-agent.com",
    "b76c5sh0-fde6.aws-agent.biz": "08233sh6-12d1.apt-agent.com",
    "fde63gz6-1y61.aws-agent.biz": "09571gz6-86k1.apt-agent.com",
}
MESL_PROXY_DNS = [
    "https://zone.rlose.com:39933/api-query",
    "https://radar.rlose.com/api-query",
]
DNS_HOST_IP_ADDITIONS = {
    "dns.alidns.com": [
        "223.5.5.5",
        "223.6.6.6",
    ],
}
REAL_IP_DOMAINS = [
    "lancache.steamcontent.com",
    "*.msftconnecttest.com",
    "*.msftncsi.com",
    "*.srv.nintendo.net",
    "*.stun.playstation.net",
    "xbox.*.microsoft.com",
    "*.xboxlive.com",
    "*.logon.battlenet.com.cn",
    "*.logon.battle.net",
    "stun.l.google.com",
    "easy-login.10099.com.cn",
    "*-update.xoyocdn.com",
    "*.prod.cloud.netflix.com",
    "appboot.netflix.com",
    "*-appboot.netflix.com",
]
BUILTIN_POLICIES = {"DIRECT", "REJECT"}
NON_SERVICE_IP_PROVIDERS = {"cn_ip", "private_ip"}

class BuildError(RuntimeError):
    pass


def unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))



def download_text(url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "egern-config-builder/1"})
    with urllib.request.urlopen(request, timeout=60) as response:
        if getattr(response, "status", 200) != 200:
            raise BuildError(f"HTTP error while fetching {url}")
        return response.read().decode("utf-8-sig")



def referenced_providers(model: dict[str, Any]) -> list[str]:
    result: list[str] = []
    for rule in model["rules"]:
        parts = rule.split(",")
        if parts[0] == "RULE-SET" and len(parts) >= 3:
            result.append(parts[1])
    for key in model.get("dns", {}).get("nameserver-policy", {}):
        if isinstance(key, str) and key.startswith("rule-set:"):
            result.append(key.removeprefix("rule-set:"))
    return unique(result)


def validate_business_ip_pairs(model: dict[str, Any]) -> None:
    rules = model["rules"]
    providers = model["providers"]
    for index, raw in enumerate(rules):
        parts = raw.split(",")
        if parts[0] != "RULE-SET" or len(parts) < 3:
            continue
        provider = parts[1]
        definition = providers.get(provider, {})
        if (
            definition.get("behavior") != "ipcidr"
            or provider in NON_SERVICE_IP_PROVIDERS
        ):
            continue
        if parts[-1] != "no-resolve":
            raise BuildError(
                f"Business IP provider must use no-resolve: {provider}"
            )
        if index == 0:
            raise BuildError(f"Business IP provider has no domain pair: {provider}")
        previous = rules[index - 1].split(",")
        previous_no_resolve = previous[-1] == "no-resolve"
        previous_policy = previous[-2] if previous_no_resolve else previous[-1]
        policy = parts[-2]
        if (
            previous[0] != "RULE-SET"
            or len(previous) < 3
            or providers.get(previous[1], {}).get("behavior") != "domain"
            or previous_policy != policy
        ):
            raise BuildError(
                f"Business IP provider must immediately follow its domain pair: {provider}"
            )


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
        if name in {"Telegram", "媒体"}:
            policies = unique(policies + ["订阅"])
        if not policies:
            policies = ["DIRECT"]
        groups.append({"select": {"name": name, "policies": unique(policies)}})
    return groups, filters


def split_nameserver_policy(value: str) -> tuple[str, str | None]:
    raw = value.strip()
    if not raw:
        raise BuildError("Mihomo DNS nameserver entry is empty")
    if "#" not in raw:
        return raw, None
    server, policy = (part.strip() for part in raw.rsplit("#", 1))
    if not server or not policy:
        raise BuildError(f"Invalid Mihomo DNS policy suffix: {value!r}")
    return server, policy


def nameserver_host(server: str) -> str:
    try:
        return str(ipaddress.ip_address(server))
    except ValueError:
        pass
    host = urlsplit(server).hostname if "://" in server else urlsplit(f"//{server}").hostname
    if not host:
        raise BuildError(f"Cannot derive a DNS server endpoint from {server!r}")
    return host.lower()


def render_nameserver_route_rules(model: dict[str, Any]) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    seen: dict[tuple[str, str], str] = {}
    for value in model.get("dns", {}).get("nameserver", []):
        if not isinstance(value, str):
            continue
        server, policy = split_nameserver_policy(value)
        if policy is None:
            continue
        host = nameserver_host(server)
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            kind = "domain"
            match = host
            item: dict[str, Any] = {"match": match, "policy": policy}
        else:
            kind = "ip_cidr" if address.version == 4 else "ip_cidr6"
            match = f"{address}/{address.max_prefixlen}"
            item = {"match": match, "policy": policy, "no_resolve": True}
        key = (kind, match)
        previous = seen.get(key)
        if previous is not None and previous != policy:
            raise BuildError(
                f"Conflicting Mihomo DNS policies for {host}: {previous!r} and {policy!r}"
            )
        if previous is None:
            seen[key] = policy
            rules.append({kind: item})
    return rules


def render_rules(
    model: dict[str, Any], provider_files: dict[str, str]
) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = [
        {"protocol": {"match": "stun", "policy": "REJECT"}},
        {
            "rule_set": {
                "match": f"{RAW_BASE}/dist/egern/{APNS_FILENAME}",
                "policy": "Proxy",
                "update_interval": 86400,
                "no_resolve": True,
            }
        }
    ]
    rules.extend(render_nameserver_route_rules(model))
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
                "match": f"{RAW_BASE}/dist/egern/{provider_files[provider]}",
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


def nameservers(model: dict[str, Any]) -> list[str]:
    result: list[str] = []
    for value in model.get("dns", {}).get("nameserver", []):
        if not isinstance(value, str):
            continue
        server, _policy = split_nameserver_policy(value)
        if server not in result:
            result.append(server)
    if not result:
        raise BuildError("Mihomo DNS model contains no nameservers")
    return result


def bootstrap_nameservers(model: dict[str, Any]) -> list[str]:
    result: list[str] = []
    for value in model.get("dns", {}).get("default-nameserver", []):
        if not isinstance(value, str):
            continue
        server, policy = split_nameserver_policy(value)
        if policy not in {None, "DIRECT"}:
            raise BuildError(
                f"Egern bootstrap is always direct and cannot preserve {policy!r} for {value!r}"
            )
        if "://" in server:
            host = urlsplit(server).hostname
        else:
            try:
                host = str(ipaddress.ip_address(server))
            except ValueError:
                host = urlsplit(f"//{server}").hostname
        if not host:
            raise BuildError(f"Cannot derive an Egern bootstrap IP from {value!r}")
        try:
            address = str(ipaddress.ip_address(host))
        except ValueError as exc:
            raise BuildError(
                f"Egern bootstrap only accepts IP addresses; cannot map {value!r}"
            ) from exc
        if address not in result:
            result.append(address)
    if not result:
        raise BuildError("Mihomo DNS model contains no usable default-nameserver IPs")
    return result


def dns_policy_target(value: Any) -> str:
    values = value if isinstance(value, list) else [value]
    cleaned = [
        item.rsplit("#", 1)[0].strip()
        for item in values
        if isinstance(item, str) and item.strip()
    ]
    if cleaned and all(item in {"system", "system://"} for item in cleaned):
        return "system"
    raise BuildError(
        "Egern DNS Forward cannot preserve this Mihomo nameserver-policy target: "
        + repr(value)
    )


def render_dns_forward(
    model: dict[str, Any],
    providers: dict[str, Any],
    provider_files: dict[str, str],
) -> list[dict[str, Any]]:
    forward: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    def add(kind: str, match: str, value: str) -> None:
        key = (kind, match, value)
        if key in seen:
            return
        seen.add(key)
        item: dict[str, Any] = {"match": match, "value": value}
        if kind == "proxy_rule_set":
            item["update_interval"] = 86400
        forward.append({kind: item})

    # User-requested APNs override is the highest-priority proxied DNS rule.
    add(
        "proxy_rule_set",
        f"{RAW_BASE}/dist/egern/{APNS_FILENAME}",
        "Foreign",
    )

    # Preserve Mihomo nameserver-policy before its general nameserver.
    for key, target in model.get("dns", {}).get("nameserver-policy", {}).items():
        if not isinstance(key, str) or not key.startswith("rule-set:"):
            raise BuildError(f"Unsupported Mihomo nameserver-policy matcher: {key!r}")
        provider = key.removeprefix("rule-set:")
        definition = providers.get(provider)
        if definition is None or definition.get("behavior") != "domain":
            raise BuildError(
                f"DNS policy references a missing or non-domain provider: {provider}"
            )
        filename = provider_files.get(provider)
        if not filename:
            raise BuildError(f"DNS policy provider was not generated: {provider}")
        add(
            "proxy_rule_set",
            f"{RAW_BASE}/dist/egern/{filename}",
            dns_policy_target(target),
        )

    # Egern has no policy-aware direct re-resolution. Preserve every explicit
    # domain rule whose final Mihomo target is Direct by selecting system DNS
    # before the foreign catch-all.
    for raw in model["rules"]:
        parts = raw.split(",")
        kind = parts[0]
        no_resolve = parts[-1] == "no-resolve"
        policy = parts[-2] if no_resolve else parts[-1]
        if policy not in {"DIRECT", "Direct"}:
            continue
        if kind == "RULE-SET" and len(parts) >= 3:
            provider = parts[1]
            definition = providers.get(provider)
            if definition is None:
                raise BuildError(f"Direct rule references missing provider: {provider}")
            if definition.get("behavior") != "domain":
                continue
            filename = provider_files.get(provider)
            if not filename:
                raise BuildError(f"Direct DNS provider was not generated: {provider}")
            add(
                "proxy_rule_set",
                f"{RAW_BASE}/dist/egern/{filename}",
                "system",
            )
        elif kind == "DOMAIN-SUFFIX" and len(parts) == 3:
            add("domain_suffix", parts[1], "system")
        elif kind == "DOMAIN" and len(parts) == 3:
            add("domain", parts[1], "system")

    add("domain_wildcard", "*", "Foreign")
    return forward


def hosts(model: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for hostname, value in model.get("hosts", {}).items():
        if isinstance(value, list):
            clean = [entry for entry in value if isinstance(entry, str) and entry]
            if clean:
                result[hostname] = clean
        elif isinstance(value, str) and value:
            result[hostname] = value
    for hostname, additions in DNS_HOST_IP_ADDITIONS.items():
        existing = result.get(hostname, [])
        if not isinstance(existing, list):
            raise BuildError(f"DNS host mapping must be an IP list: {hostname}")
        result[hostname] = unique(existing + additions)
    result.update(FLOWER_HOSTS)
    return result


def validate_profile(
    profile: dict[str, Any],
    generated: dict[str, dict[str, Any]],
    model: dict[str, Any],
    provider_files: dict[str, str],
) -> None:
    groups = [next(iter(item.values())) for item in profile["policy_groups"]]
    names = [item["name"] for item in groups]
    if len(names) != len(set(names)):
        raise BuildError("Policy group names are not unique")
    known = set(names) | BUILTIN_POLICIES
    if APNS_FILENAME not in generated:
        raise BuildError("APNs native rule set was not generated")
    first_rule = profile["rules"][0].get("protocol", {})
    if first_rule != {"match": "stun", "policy": "REJECT"}:
        raise BuildError("STUN blocking must be the first routing rule")
    apns_rule = profile["rules"][1].get("rule_set", {})
    if (
        apns_rule.get("match") != f"{RAW_BASE}/dist/egern/{APNS_FILENAME}"
        or apns_rule.get("policy") != "Proxy"
        or apns_rule.get("no_resolve") is not True
    ):
        raise BuildError("APNs rule set must immediately follow STUN blocking and use Proxy")
    expected_nameserver_routes = render_nameserver_route_rules(model)
    if profile["rules"][2:2 + len(expected_nameserver_routes)] != expected_nameserver_routes:
        raise BuildError("Mihomo DNS nameserver policy suffixes were not preserved")
    first_dns_rule = profile["dns"]["forward"][0].get("proxy_rule_set", {})
    if (
        first_dns_rule.get("match") != f"{RAW_BASE}/dist/egern/{APNS_FILENAME}"
        or first_dns_rule.get("value") != "Foreign"
    ):
        raise BuildError("APNs rule set must be the first DNS Forward rule and use Foreign")
    for group in groups:
        for policy in group.get("policies", []):
            if policy not in known:
                raise BuildError(f"Group {group['name']} references undefined policy {policy}")
    if profile["policy_groups"][names.index("订阅")]["select"].get("urls") != []:
        raise BuildError("Public profile must not contain subscription credentials")
    if profile.get("default_subscription_group") != "订阅":
        raise BuildError("Egern default subscription group must be 订阅")
    if profile.get("default_proxy_group") != "代理":
        raise BuildError("Egern default proxy group must be 代理")
    if "auto_update" in profile:
        raise BuildError("Egern profile updates must remain manual to preserve local subscriptions")
    for target in ("Telegram", "媒体"):
        if target not in names:
            raise BuildError(f"Required policy group is missing: {target}")
        if "订阅" not in groups[names.index(target)].get("policies", []):
            raise BuildError(f"{target} must include the 订阅 policy group")
    for provider, filename in provider_files.items():
        native_rule = generated[filename]
        if any(
            field in native_rule
            for field in ("ip_cidr_set", "ip_cidr6_set", "asn_set", "geoip_set")
        ) and native_rule.get("no_resolve") is not True:
            raise BuildError(
                f"IP-capable native rule set must use no_resolve: {provider}"
            )
    routing_offset = 2 + len(expected_nameserver_routes)
    for source_index, raw in enumerate(model["rules"]):
        parts = raw.split(",")
        if (
            parts[0] == "RULE-SET"
            and len(parts) >= 3
            and model["providers"].get(parts[1], {}).get("behavior") == "ipcidr"
            and parts[1] not in NON_SERVICE_IP_PROVIDERS
        ):
            rendered = profile["rules"][routing_offset + source_index].get("rule_set", {})
            if rendered.get("no_resolve") is not True:
                raise BuildError(
                    f"Rendered business IP rule must use no_resolve: {parts[1]}"
                )
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
    if profile.get("hijack_dns") != ["*:53"]:
        raise BuildError("Egern DNS hijacking must target port 53")
    if profile.get("include_all_networks") is not True:
        raise BuildError("Egern must include all system network traffic")
    if profile.get("include_apns") is not True:
        raise BuildError("Egern must include APNs traffic")
    if "close_connections_on_policy_change" in profile:
        raise BuildError("Unsourced Egern connection-closing behavior must not be enabled")
    if dns.get("bootstrap") != bootstrap_nameservers(model):
        raise BuildError("Mihomo default-nameserver was not preserved as Egern bootstrap")
    expected_forward = render_dns_forward(model, model["providers"], provider_files)
    if dns.get("forward") != expected_forward:
        raise BuildError("Mihomo DNS policy and Direct-domain DNS were not preserved")
    if dns.get("proxy_nameservers") != MESL_PROXY_DNS:
        raise BuildError("MESL proxy nameservers were not preserved")
    if profile.get("real_ip_domains") != REAL_IP_DOMAINS:
        raise BuildError("Repcz real-IP domain exclusions were not preserved")
    for hostname, additions in DNS_HOST_IP_ADDITIONS.items():
        current = dns["hosts"].get(hostname)
        if not isinstance(current, list) or any(
            address not in current for address in additions
        ):
            raise BuildError(f"Required DNS host IPs missing: {hostname}")
    for hostname, target in FLOWER_HOSTS.items():
        if dns["hosts"].get(hostname) != target:
            raise BuildError(f"Flower host mapping missing: {hostname}")



def load_manifest_rules(
    model: dict[str, Any], manifest: dict[str, Any], converter_commit: str
) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    if manifest.get("schema_version") != 1:
        raise BuildError("Unsupported Egern rule manifest schema")
    if manifest.get("mihomo_script", {}).get("repository") != MIHOMO_REPO:
        raise BuildError("Rule manifest has an unexpected Mihomo repository")
    records = manifest.get("native_rule_sets")
    wanted = referenced_providers(model)
    if not isinstance(records, list) or [
        record.get("provider") for record in records if isinstance(record, dict)
    ] != ["apns", *wanted] or len(records) != len(wanted) + 1:
        raise BuildError("Rule manifest does not match the Mihomo provider model")

    generated: dict[str, dict[str, Any]] = {}
    provider_files: dict[str, str] = {}
    for record in records:
        name = record["provider"]
        output = record.get("output")
        if (
            not isinstance(output, str)
            or not re.fullmatch(r"dist/egern/[A-Za-z0-9.-]+\.yaml", output)
        ):
            raise BuildError(f"Invalid published Egern rule path for {name}")
        filename = Path(output).name
        if filename in generated:
            raise BuildError(f"Duplicate published Egern rule path: {filename}")
        if name == "apns":
            if (
                output != "dist/egern/apns.yaml"
                or record.get("source_repository") != "ttyyss2233/Tool"
                or record.get("source_path") != "shadowrocket/rules/apns.list"
            ):
                raise BuildError("APNs rule manifest source or path changed")
        else:
            provider = model["providers"].get(name)
            if (
                provider is None
                or record.get("provider_url") != provider.get("url")
                or record.get("behavior") != provider.get("behavior")
            ):
                raise BuildError(f"Rule manifest source differs from Mihomo: {name}")
            provider_files[name] = filename
        if record.get("source_entries") != record.get("entries") or not isinstance(
            record.get("entries"), int
        ) or record["entries"] <= 0:
            raise BuildError(f"Rule manifest entry count changed: {name}")
        expected_sha = record.get("output_sha256")
        if not isinstance(expected_sha, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_sha):
            raise BuildError(f"Rule manifest output hash is missing: {name}")
        url = f"https://raw.githubusercontent.com/{CONVERTER_REPO}/{converter_commit}/{output}"
        rule_text = download_text(url)
        if hashlib.sha256(rule_text.encode("utf-8")).hexdigest() != expected_sha:
            raise BuildError(f"Published Egern rule hash differs from manifest: {name}")
        rule = yaml.safe_load(rule_text)
        if not isinstance(rule, dict):
            raise BuildError(f"Published Egern rule is not YAML mapping: {name}")
        entries = sum(len(value) for value in rule.values() if isinstance(value, list))
        if entries != record["entries"]:
            raise BuildError(f"Published Egern rule count differs from manifest: {name}")
        generated[filename] = rule
    return generated, provider_files


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
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--mihomo-commit", required=True)
    parser.add_argument("--converter-commit", required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    try:
        model = json.loads(args.model.read_text(encoding="utf-8"))
        manifest_text = args.manifest.read_text(encoding="utf-8")
        manifest = json.loads(manifest_text)
        if manifest.get("mihomo_script", {}).get("commit") != args.mihomo_commit:
            raise BuildError("Mihomo script commit differs from converter rule manifest")
        validate_business_ip_pairs(model)
        generated, provider_files = load_manifest_rules(model, manifest, args.converter_commit)
        groups, filters = render_policy_groups(model)
        rules = render_rules(model, provider_files)
        profile = {
            "ipv6": True,
            "hijack_dns": ["*:53"],
            "block_quic": False,
            "include_all_networks": True,
            "include_apns": True,
            "real_ip_domains": REAL_IP_DOMAINS,
            "default_subscription_group": "订阅",
            "default_proxy_group": "代理",
            "dns": {
                "bootstrap": bootstrap_nameservers(model),
                "upstreams": {"Foreign": nameservers(model)},
                "forward": render_dns_forward(model, model["providers"], provider_files),
                "hosts": hosts(model),
                "proxy_nameservers": MESL_PROXY_DNS,
            },
            "policy_groups": groups,
            "rules": rules,
        }
        validate_profile(profile, generated, model, provider_files)

        profile_text = yaml.safe_dump(profile, allow_unicode=True, sort_keys=False, width=1000)
        report_data = {
            "schema_version": 3,
            "mihomo_script": manifest["mihomo_script"],
            "proxy_rules_converter": {
                "repository": CONVERTER_REPO,
                "branch": "main",
                "commit": args.converter_commit,
                "manifest_path": CONVERTER_MANIFEST_PATH,
                "manifest_sha256": hashlib.sha256(manifest_text.encode("utf-8")).hexdigest(),
            },
            "profile_sha256": hashlib.sha256(profile_text.encode("utf-8")).hexdigest(),
            "policy_groups": len(groups),
            "routing_rules": len(rules),
            "native_rule_sets": manifest["native_rule_sets"],
            "group_filters": filters,
            "dns": {
                "bootstrap": profile["dns"]["bootstrap"],
                "forward_rules": len(profile["dns"]["forward"]),
                "nameserver_route_rules": len(render_nameserver_route_rules(model)),
                "proxy_nameservers": profile["dns"]["proxy_nameservers"],
            },
            "subscription": {
                "group": "订阅",
                "default_subscription_group": profile["default_subscription_group"],
                "default_proxy_group": profile["default_proxy_group"],
                "urls_published": False,
                "reason": "Default group names are public; subscription credentials remain local.",
            },
            "migration_boundaries": [
                "Mihomo IPv4/IPv6 preferred DIRECT pseudo-proxies map to Egern DIRECT.",
                "Mihomo default-nameserver endpoints map to plain-UDP bootstrap IPs because Egern bootstrap only supports plain UDP.",
                "Mihomo nameserver policy suffixes map to explicit Egern routing rules for the DNS server endpoints.",
                "Mihomo nameserver-policy and explicit Direct domain rules map to Egern Forward system rules; Egern cannot re-resolve from a runtime policy-group selection.",
                "The explicit Egern real_ip_domains list mirrors Repcz/Tool X/Egern/Egern.yaml; other Fake-IP behavior follows Egern defaults.",
                "The user-requested STUN block is emitted as the first Egern routing rule with REJECT.",
                "The converter's APNs rule set follows STUN blocking with Proxy/Foreign DNS handling.",
                "Egern-native rule conversion and source provenance are published by proxy-rules-converter.",
                "Every paired business IP rule must immediately follow its domain rule and use Egern no_resolve; standalone mainland/private IP fallbacks preserve Mihomo routing semantics.",
            ],
        }
        report_text = json.dumps(report_data, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        changed: list[str] = []
        if write_or_check(PROFILE_PATH, profile_text, args.check):
            changed.append("Profile.yaml")
        if write_or_check(REPORT_PATH, report_text, args.check):
            changed.append("reports/source.json")
        if args.check and changed:
            raise BuildError("Generated files are out of date: " + ", ".join(changed))
        print(f"Generated {len(groups)} policy groups and {len(rules)} routing rules; verified {len(generated)} published rule sets.")
        return 0
    except (BuildError, OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, yaml.YAMLError) as exc:
        print(f"Build failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
