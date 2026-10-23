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
LEGACY_DNS_ROUTE_EXCLUDED_HOSTS = {"cloudflare-dns.com", "dns.google"}

class BuildError(RuntimeError):
    pass


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
    return list(dict.fromkeys(result))


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
    if not bodies:
        return ".*"
    prefix = "(?i)" if insensitive else ""
    return prefix + "^(?!.*(?:" + "|".join(bodies) + ")).*$"


def render_policy_groups(model: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, str]]:
    regions = {entry["name"]: regex_text(entry) for entry in model["regions"]}
    rates = {entry["name"]: regex_text(entry) for entry in model["rateRegions"]}
    excluded: list[str] = []
    if model["options"].get("过滤非地区节点"):
        excluded.append(regex_text(model["excludeFilter"]))
    if model["options"].get("过滤低倍率节点"):
        excluded.extend(rates.values())

    filters: dict[str, str] = {"订阅": negative_filter(excluded)}
    display_name = {"台湾省": "台湾"}
    for source_name, pattern in regions.items():
        filters[display_name.get(source_name, source_name)] = pattern
    filters.update(rates)
    filters["其他节点"] = negative_filter(list(regions.values()))

    if any(source["name"] == "订阅2" for source in model["groups"]):
        raise BuildError("Mihomo already defines the local 订阅2 group")
    groups: list[dict[str, Any]] = []
    for source in model["groups"]:
        name = source["name"]
        if name == "pron":
            groups.append({"select": {"name": name, "policies": ["香港", "新加坡"]}})
            continue
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
            groups.append({"select": {"name": "订阅2", "policies": [], "urls": [], "filter": filters[name]}})
            continue
        if name in filters and name != "订阅":
            groups.append({
                "select": {
                    "name": name,
                    "policies": ["订阅", "订阅2"] if name == "香港" else ["订阅"],
                    "flatten": True,
                    "filter": filters[name],
                }
            })
            continue
        policies = [
            value for value in source.get("proxies", [])
            if not value.startswith("__") and value not in {"IPv4优先", "IPv6优先"}
        ]
        if name == "Proxy":
            policies = ["订阅", "订阅2"] + [
                policy for policy in policies if policy not in {"订阅", "订阅2"}
            ]
            groups.append({"select": {"name": name, "policies": policies, "flatten": True}})
            continue
        if name == "Direct":
            policies = ["DIRECT"]
        if name == "Google" and "订阅" not in policies:
            policies.append("订阅")
        if name in {"Telegram", "媒体", "PikPak"} and "香港" not in policies:
            policies.append("香港")
        if name in {"Telegram", "媒体"}:
            for subscription in ("订阅", "订阅2"):
                if subscription not in policies:
                    policies.append(subscription)
        if not policies:
            policies = ["DIRECT"]
        groups.append({"select": {"name": name, "policies": policies}})
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


def render_rules(
    model: dict[str, Any], provider_files: dict[str, list[str]]
) -> list[dict[str, Any]]:
    """Prepend APNs, then translate every Mihomo rule exactly once in source order."""
    rules: list[dict[str, Any]] = []
    for filename in provider_files.get("apns", [APNS_FILENAME]):
        rules.append({
            "rule_set": {
                "match": f"{RAW_BASE}/dist/egern/{filename}",
                "policy": "Proxy",
                "update_interval": 86400,
                "no_resolve": True,
            }
        })
    for raw in model["rules"]:
        parts = raw.split(",")
        kind = parts[0]
        if kind == "MATCH" and len(parts) == 2:
            rules.append({"default": {"policy": parts[1]}})
        elif kind == "RULE-SET" and (
            len(parts) == 3 or (len(parts) == 4 and parts[-1] == "no-resolve")
        ):
            provider = parts[1]
            filenames = provider_files.get(provider)
            if not filenames or len(filenames) != 1:
                raise BuildError(f"Expected one native file for Mihomo provider: {provider}")
            no_resolve = len(parts) == 4
            item: dict[str, Any] = {
                "match": f"{RAW_BASE}/dist/egern/{filenames[0]}",
                "policy": parts[2],
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


def validate_rule_alignment(
    rules: list[dict[str, Any]],
    model: dict[str, Any],
    provider_files: dict[str, list[str]],
) -> None:
    """Reverse the published rules and compare them with the untouched source list."""
    apns_files = provider_files.get("apns", [APNS_FILENAME])
    if apns_files != [APNS_FILENAME] or not rules or rules[0] != {
        "rule_set": {
            "match": f"{RAW_BASE}/dist/egern/{APNS_FILENAME}",
            "policy": "Proxy",
            "update_interval": 86400,
            "no_resolve": True,
        }
    }:
        raise BuildError("Exactly one APNs rule must be first")
    provider_by_url = {
        f"{RAW_BASE}/dist/egern/{filename}": provider
        for provider, filenames in provider_files.items()
        if provider != "apns"
        for filename in filenames
    }
    actual: list[str] = []
    kinds = {"domain": "DOMAIN", "domain_suffix": "DOMAIN-SUFFIX"}
    for wrapper in rules[1:]:
        if len(wrapper) != 1:
            raise BuildError("Routing rule must contain exactly one matcher")
        kind, item = next(iter(wrapper.items()))
        if kind == "rule_set":
            provider = provider_by_url.get(item.get("match"))
            if provider is None or set(item) - {"match", "policy", "update_interval", "no_resolve"}:
                raise BuildError("Unexpected rule set outside the Mihomo model")
            if item.get("update_interval") != 86400:
                raise BuildError("Rule-set update interval changed")
            raw = f"RULE-SET,{provider},{item['policy']}"
            if "no_resolve" in item:
                if item["no_resolve"] is not True:
                    raise BuildError("Invalid no_resolve flag")
                raw += ",no-resolve"
        elif kind == "default" and set(item) == {"policy"}:
            raw = f"MATCH,{item['policy']}"
        elif kind in kinds and set(item) == {"match", "policy"}:
            raw = f"{kinds[kind]},{item['match']},{item['policy']}"
        else:
            raise BuildError(f"Unexpected routing matcher: {kind}")
        actual.append(raw)
    if actual != model["rules"]:
        raise BuildError(
            "Egern routing differs from Mihomo in order, count, policy, or no-resolve; "
            "APNs is the only permitted extra rule"
        )


def nameservers(model: dict[str, Any]) -> list[str]:
    result: list[str] = []
    for value in model.get("dns", {}).get("nameserver", []):
        if not isinstance(value, str):
            continue
        server, policy = split_nameserver_policy(value)
        if policy is not None and (
            urlsplit(server).hostname not in LEGACY_DNS_ROUTE_EXCLUDED_HOSTS or policy != "Proxy"
        ):
            raise BuildError(
                "DNS routing suffix requires an explicit rule in the Mihomo source; "
                f"Egern cannot inject endpoint routing rules: {value!r}"
            )
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
        result.append(address)
    if not result:
        raise BuildError("Mihomo DNS model contains no usable default-nameserver IPs")
    return result


def dns_policy_servers(value: Any) -> list[str]:
    values = value if isinstance(value, list) else [value]
    if not values or any(not isinstance(item, str) or not item.strip() for item in values):
        raise BuildError(f"Invalid Mihomo nameserver-policy target: {value!r}")
    servers: list[str] = []
    for item in values:
        server, suffix = split_nameserver_policy(item)
        if suffix not in {None, "DIRECT"}:
            raise BuildError(f"Unsupported nameserver-policy route: {item!r}")
        if server in {"system", "system://"}:
            servers.append("system")
            continue
        try:
            ipaddress.ip_address(server)
        except ValueError as exc:
            raise BuildError(f"Unsupported Mihomo nameserver-policy server: {item!r}") from exc
        servers.append(server)
    return servers


def dns_policy_target(value: Any, provider: str) -> str:
    servers = dns_policy_servers(value)
    if all(server == "system" for server in servers):
        return "system"
    if not re.fullmatch(r"[A-Za-z0-9_-]+", provider):
        raise BuildError(f"Invalid DNS policy provider name: {provider!r}")
    return "Policy-" + provider.replace("_", "-")


def render_dns_upstreams(model: dict[str, Any]) -> dict[str, list[str]]:
    upstreams = {"Foreign": nameservers(model)}
    for key, target in model.get("dns", {}).get("nameserver-policy", {}).items():
        if not isinstance(key, str) or not key.startswith("rule-set:"):
            raise BuildError(f"Unsupported Mihomo nameserver-policy matcher: {key!r}")
        provider = key.removeprefix("rule-set:")
        group = dns_policy_target(target, provider)
        if group != "system":
            servers = dns_policy_servers(target)
            if group in upstreams and upstreams[group] != servers:
                raise BuildError(f"Conflicting DNS policy upstream group: {group}")
            upstreams[group] = servers
    return upstreams


def render_dns_forward(
    model: dict[str, Any],
    providers: dict[str, Any],
    provider_files: dict[str, list[str]],
) -> list[dict[str, Any]]:
    forward: list[dict[str, Any]] = []

    def add(kind: str, match: str, value: str) -> None:
        item: dict[str, Any] = {"match": match, "value": value}
        if kind == "proxy_rule_set":
            item["update_interval"] = 86400
        forward.append({kind: item})

    # User-requested APNs override is the highest-priority proxied DNS rule.
    for filename in provider_files.get("apns", [APNS_FILENAME]):
        add("proxy_rule_set", f"{RAW_BASE}/dist/egern/{filename}", "Foreign")

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
        filenames = provider_files.get(provider)
        if not filenames:
            raise BuildError(f"DNS policy provider was not generated: {provider}")
        for filename in filenames:
            add(
                "proxy_rule_set",
                f"{RAW_BASE}/dist/egern/{filename}",
                dns_policy_target(target, provider),
            )

    # Egern has no policy-aware direct re-resolution. Preserve every explicit
    # domain rule whose final Mihomo target is Direct by selecting system DNS
    # before the foreign catch-all.
    policy_providers = {
        key.removeprefix("rule-set:")
        for key in model.get("dns", {}).get("nameserver-policy", {})
    }
    for raw in model["rules"]:
        parts = raw.split(",")
        kind = parts[0]
        no_resolve = parts[-1] == "no-resolve"
        policy = parts[-2] if no_resolve else parts[-1]
        if policy not in {"DIRECT", "Direct"}:
            continue
        if kind == "RULE-SET" and len(parts) >= 3:
            provider = parts[1]
            # Explicit DNS policy already handles this matcher, even if its target
            # differs. Do not synthesize an unreachable second forwarding rule.
            if provider in policy_providers:
                continue
            definition = providers.get(provider)
            if definition is None:
                raise BuildError(f"Direct rule references missing provider: {provider}")
            if definition.get("behavior") != "domain":
                continue
            filenames = provider_files.get(provider)
            if not filenames:
                raise BuildError(f"Direct DNS provider was not generated: {provider}")
            for filename in filenames:
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
        result[hostname] = existing + [address for address in additions if address not in existing]
    result.update(FLOWER_HOSTS)
    return result


def validate_profile(
    profile: dict[str, Any],
    generated: dict[str, dict[str, Any]],
    model: dict[str, Any],
    provider_files: dict[str, list[str]],
) -> None:
    groups = [next(iter(item.values())) for item in profile["policy_groups"]]
    names = [item["name"] for item in groups]
    if len(names) != len(set(names)):
        raise BuildError("Policy group names are not unique")
    if "Proxy" not in names:
        raise BuildError("Proxy policy group is missing")
    proxy_group = groups[names.index("Proxy")]
    if (
        proxy_group.get("flatten") is not True
        or proxy_group.get("policies", [])[:2] != ["订阅", "订阅2"]
        or "filter" in proxy_group
    ):
        raise BuildError("Proxy must flatten all nodes from both subscription groups without a regional filter")
    known = set(names) | BUILTIN_POLICIES
    apns_files = provider_files.get("apns", [])
    if any(filename not in generated for filename in apns_files):
        raise BuildError("APNs native rule set was not generated")
    validate_rule_alignment(profile["rules"], model, provider_files)
    for index, filename in enumerate(apns_files):
        first_dns_rule = profile["dns"]["forward"][index].get("proxy_rule_set", {})
        if (
            first_dns_rule.get("match") != f"{RAW_BASE}/dist/egern/{filename}"
            or first_dns_rule.get("value") != "Foreign"
        ):
            raise BuildError("APNs DNS Forward rule set must be first")
    for group in groups:
        for policy in group.get("policies", []):
            if policy not in known:
                raise BuildError(f"Group {group['name']} references undefined policy {policy}")
    if profile["policy_groups"][names.index("订阅")]["select"].get("urls") != []:
        raise BuildError("Public profile must not contain subscription credentials")
    subscription_two = profile["policy_groups"][names.index("订阅2")]["select"]
    if subscription_two.get("policies") != [] or subscription_two.get("urls") != []:
        raise BuildError("订阅2 must start with no policy options or subscription URLs")
    if subscription_two.get("filter") != profile["policy_groups"][names.index("订阅")]["select"].get("filter"):
        raise BuildError("订阅2 must use the same exclusion filter as 订阅")
    if profile.get("default_subscription_group") != "订阅":
        raise BuildError("Egern default subscription group must be 订阅")
    if profile.get("default_proxy_group") != "代理":
        raise BuildError("Egern default proxy group must be 代理")
    if "auto_update" in profile:
        raise BuildError("Egern profile updates must remain manual to preserve local subscriptions")
    if "香港" not in names:
        raise BuildError("Hong Kong group is missing")
    hong_kong_group = groups[names.index("香港")]
    if (
        hong_kong_group.get("policies") != ["订阅", "订阅2"]
        or hong_kong_group.get("flatten") is not True
        or hong_kong_group.get("filter") != regex_text(next(entry for entry in model["regions"] if entry["name"] == "香港"))
    ):
        raise BuildError("Hong Kong group must filter both subscription groups")
    for target in ("YouTube", "媒体", "PikPak", "Telegram"):
        if target not in names or "香港" not in groups[names.index(target)].get("policies", []):
            raise BuildError(f"{target} must include the Hong Kong policy group")
    if (
        "pron" not in names
        or groups[names.index("pron")].get("policies") != ["香港", "新加坡"]
        or groups[names.index("pron")].get("flatten", False)
    ):
        raise BuildError("pron must offer Hong Kong and Singapore groups without flattening nodes")
    for target in ("Telegram", "媒体"):
        if target not in names:
            raise BuildError(f"Required policy group is missing: {target}")
        for subscription in ("订阅", "订阅2"):
            if subscription not in groups[names.index(target)].get("policies", []):
                raise BuildError(f"{target} must include the {subscription} policy group")
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
    if profile.get("close_connections_on_policy_change") is not True:
        raise BuildError("Egern must close old connections when a policy group selection changes")
    if dns.get("bootstrap") != bootstrap_nameservers(model):
        raise BuildError("Mihomo default-nameserver was not preserved as Egern bootstrap")
    if dns.get("upstreams") != render_dns_upstreams(model):
        raise BuildError("Mihomo nameserver-policy upstreams were not preserved")
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
) -> tuple[dict[str, dict[str, Any]], dict[str, list[str]]]:
    if manifest.get("schema_version") != 3:
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
    provider_files: dict[str, list[str]] = {}
    # Optional converter-only artifacts are not Egern routing exceptions.
    for record in records:
        name = record["provider"]
        if name == "apns":
            if (
                record.get("source_repository") != "ttyyss2233/Tool"
                or record.get("source_path") != "shadowrocket/rules/apns.list"
            ):
                raise BuildError("APNs rule manifest source changed")
        else:
            provider = model["providers"].get(name)
            if (
                provider is None
                or record.get("provider_url") != provider.get("url")
                or record.get("behavior") != provider.get("behavior")
            ):
                raise BuildError(f"Rule manifest source differs from Mihomo: {name}")
        if record.get("source_entries") != record.get("entries") or not isinstance(
            record.get("entries"), int
        ) or record["entries"] <= 0:
            raise BuildError(f"Rule manifest entry count changed: {name}")
        output = record.get("output")
        if (
            not isinstance(output, str)
            or not re.fullmatch(r"dist/egern/[A-Za-z0-9.-]+\.yaml", output)
        ):
            raise BuildError(f"Invalid published Egern rule path for {name}")
        filename = Path(output).name
        if filename in generated:
            raise BuildError(f"Duplicate published Egern rule path: {filename}")
        expected_sha = record.get("output_sha256")
        native_sha = record.get("native_entries_sha256")
        source_order_sha = record.get("source_order_sha256")
        if any(
            not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)
            for value in (expected_sha, native_sha, source_order_sha)
        ):
            raise BuildError(f"Rule manifest digest is missing: {name}")
        url = f"https://raw.githubusercontent.com/{CONVERTER_REPO}/{converter_commit}/{output}"
        rule_text = download_text(url)
        if hashlib.sha256(rule_text.encode("utf-8")).hexdigest() != expected_sha:
            raise BuildError(f"Published Egern rule hash differs from manifest: {name}")
        rule = yaml.safe_load(rule_text)
        if not isinstance(rule, dict):
            raise BuildError(f"Published Egern rule is not YAML mapping: {name}")
        sequence: list[tuple[str, str]] = []
        for field, values in rule.items():
            if isinstance(values, list):
                if not values or any(not isinstance(value, str) for value in values):
                    raise BuildError(f"Invalid Egern rule entries: {name}/{field}")
                sequence.extend((field, value) for value in values)
            elif field != "no_resolve" or values is not True:
                raise BuildError(f"Invalid Egern rule field: {name}/{field}")
        if len(sequence) != record["entries"]:
            raise BuildError(f"Published Egern rule count differs from manifest: {name}")
        computed_native_sha = hashlib.sha256(
            json.dumps(sequence, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        if computed_native_sha != native_sha:
            raise BuildError(f"Published Egern native rule order differs from manifest: {name}")
        if any(field in rule for field in ("ip_cidr_set", "ip_cidr6_set", "asn_set", "geoip_set")):
            if rule.get("no_resolve") is not True:
                raise BuildError(f"Published Egern IP rules must disable resolution: {name}")
        generated[filename] = rule
        provider_files[name] = [filename]
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
        generated, provider_files = load_manifest_rules(model, manifest, args.converter_commit)
        groups, filters = render_policy_groups(model)
        rules = render_rules(model, provider_files)
        profile = {
            "ipv6": True,
            "hijack_dns": ["*:53"],
            "block_quic": False,
            "close_connections_on_policy_change": True,
            "include_all_networks": True,
            "include_apns": True,
            "real_ip_domains": REAL_IP_DOMAINS,
            "default_subscription_group": "订阅",
            "default_proxy_group": "代理",
            "dns": {
                "bootstrap": bootstrap_nameservers(model),
                "upstreams": render_dns_upstreams(model),
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
            "schema_version": 4,
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
            "ignored_egern_only_providers": [
                record.get("provider")
                for record in manifest.get("egern_only_rule_sets", [])
                if isinstance(record, dict)
            ],
            "routing_alignment": {
                "only_apns_exception": True,
                "apns_rules": 1,
                "mihomo_rules": model["rules"],
                "shared_rule_count": len(model["rules"]),
            },
            "group_filters": filters,
            "dns": {
                "bootstrap": profile["dns"]["bootstrap"],
                "forward_rules": len(profile["dns"]["forward"]),
                "upstreams": profile["dns"]["upstreams"],
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
                "APNs is the only routing exception: one Proxy rule is prepended and its DNS Forward uses Foreign.",
                "All remaining routing rules preserve the Mihomo source order, duplicates, policies, and no-resolve flags exactly.",
                "Private, MCDN, Claude/AI, Steam, and all other providers have no Egern-specific reordering or target overrides.",
                "Optional converter-only rule sets are not loaded or inserted into the profile.",
                "The pron policy group keeps the source name; local subscription and service-group choices remain Egern settings.",
                "Mihomo IPv4/IPv6 preferred DIRECT pseudo-proxies map to Egern DIRECT.",
                "Mihomo default-nameserver IPs retain their order as plain-UDP Egern bootstrap.",
                "The two legacy excluded DoH endpoint suffixes retain upstream URLs without injected routing; any new suffix fails explicitly.",
                "Mihomo nameserver-policy becomes ordered DNS Forward rules; additional static Direct matchers use system without duplicating a provider already covered by explicit DNS policy.",
                "Source duplicates remain intact; only redundant synthesized DNS Forward entries are omitted.",
                "Egern cannot reproduce Mihomo runtime direct-nameserver re-resolution after a policy-group selection changes.",
                "Real-IP exclusions, MESL proxy DNS, AliDNS host additions, Flower aliases, and subscription defaults remain explicit Egern settings.",
                "Egern-native rules are fetched at the converter commit and verified against manifest hashes, entry counts, and native-field-order digests.",
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
