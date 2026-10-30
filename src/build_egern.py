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
PRIVATERELAY_PROVIDER = "privaterelay"
PRIVATERELAY_FILENAME = "privaterelay.yaml"
POLICY_ALIASES = {"pron": "porn", "Apple Podcasts": "媒体"}
FLOWER_HOSTS = {
    "11612bj3-b76c.aws-agent.biz": "06996bj6-79x5.apt-agent.com",
    "b76c5sh0-fde6.aws-agent.biz": "08233sh6-12d1.apt-agent.com",
    "fde63gz6-1y61.aws-agent.biz": "09571gz6-86k1.apt-agent.com",
}
MESL_PROXY_NAMESERVERS = (
    "https://zone.rlose.com:39933/api-query",
    "https://radar.rlose.com/api-query",
)
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
        # Logical rules can reference providers at any nesting depth.
        result.extend(re.findall(r"\bRULE-SET,([^,()]+)", rule))
    for key in model.get("dns", {}).get("nameserver-policy", {}):
        if isinstance(key, str) and key.startswith("rule-set:"):
            result.append(key.removeprefix("rule-set:"))
    return list(dict.fromkeys(result))


def apply_dns_model(model: dict[str, Any], dns_model: dict[str, Any]) -> dict[str, Any]:
    for key in dns_model["dns"].get("nameserver-policy", {}):
        if not isinstance(key, str) or not key.startswith("rule-set:"):
            raise BuildError(f"Unsupported Mihomo nameserver-policy matcher: {key!r}")
        provider = key.removeprefix("rule-set:")
        pinned = model["providers"].get(provider)
        current = dns_model["providers"].get(provider)
        if (not pinned or not current or current.get("behavior") != "domain"
                or any(pinned.get(field) != current.get(field) for field in ("url", "behavior", "format"))):
            raise BuildError(f"DNS provider differs from converter snapshot: {provider}")
    return {**model, "dns": dns_model["dns"]}


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


def rate_filter(entry: dict[str, str]) -> str:
    pattern = regex_text(entry)
    return pattern + "|实验" if entry["name"] == "低倍率节点" else pattern


def render_policy_groups(model: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, str]]:
    regions = {entry["name"]: regex_text(entry) for entry in model["regions"]}
    rates = {entry["name"]: rate_filter(entry) for entry in model["rateRegions"]}
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
        if source["name"] == "Apple Podcasts":
            continue
        name = POLICY_ALIASES.get(source["name"], source["name"])
        if name == "porn":
            groups.append({"select": {"name": name, "policies": ["香港", "新加坡", "美国", "低倍率节点"]}})
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
                    "policies": ["订阅", "订阅2"],
                    "flatten": True,
                    "filter": filters[name],
                }
            })
            continue
        policies = [
            POLICY_ALIASES.get(value, value) for value in source.get("proxies", [])
            if not value.startswith("__") and value not in {"IPv4优先", "IPv6优先"}
        ]
        if name == "Proxy":
            policies = ["订阅", "订阅2"] + [
                policy for policy in policies if policy not in {"订阅", "订阅2"}
            ]
            groups.append({"select": {"name": name, "policies": policies, "flatten": False}})
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
        if name == "EHentai":
            for choice in ("美国", "新加坡", "低倍率节点"):
                if choice not in policies:
                    policies.append(choice)
        if name == "媒体":
            for region in ("美国", "日本"):
                if region not in policies:
                    policies.append(region)
        policies = list(dict.fromkeys(policies))
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


def split_rule(text: str) -> list[str]:
    parts: list[str] = []
    start = depth = 0
    for index, character in enumerate(text):
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth < 0:
                raise BuildError(f"Unbalanced logical rule: {text}")
        elif character == "," and depth == 0:
            parts.append(text[start:index])
            start = index + 1
    if depth:
        raise BuildError(f"Unbalanced logical rule: {text}")
    parts.append(text[start:])
    return parts


def unwrap_rule(text: str) -> str:
    if not text.startswith("(") or not text.endswith(")"):
        raise BuildError(f"Expected parenthesized condition: {text}")
    value = text[1:-1]
    split_rule(value)
    return value


def render_condition(text: str, provider_files: dict[str, list[str]]) -> dict[str, Any]:
    parts = split_rule(text)
    kind = parts[0]
    if kind in {"AND", "OR", "NOT"} and len(parts) == 2:
        children = [
            render_condition(unwrap_rule(child), provider_files)
            for child in split_rule(unwrap_rule(parts[1]))
        ]
        if not children or (kind == "NOT" and len(children) != 1):
            raise BuildError(f"Invalid logical operands: {text}")
        return {kind.lower(): {"match": children[0] if kind == "NOT" else children}}
    if kind == "RULE-SET" and (len(parts) == 2 or len(parts) == 3 and parts[2] == "no-resolve"):
        files = provider_files.get(parts[1], [])
        if len(files) != 1:
            raise BuildError(f"Expected one native condition file: {parts[1]}")
        value: dict[str, Any] = {
            "match": f"{RAW_BASE}/dist/egern/{files[0]}", "update_interval": 86400,
        }
        if len(parts) == 3:
            value["no_resolve"] = True
        return {"rule_set": value}
    kinds = {"NETWORK": "protocol", "DST-PORT": "dest_port", "DOMAIN": "domain", "DOMAIN-SUFFIX": "domain_suffix"}
    if kind in kinds and len(parts) == 2:
        value = parts[1].lower() if kind == "NETWORK" else parts[1]
        return {kinds[kind]: {"match": value}}
    raise BuildError(f"Unsupported logical condition: {text}")


def restore_condition(wrapper: dict[str, Any], provider_by_url: dict[str, str]) -> str:
    if len(wrapper) != 1:
        raise BuildError("Logical condition requires one matcher")
    kind, value = next(iter(wrapper.items()))
    if kind in {"and", "or", "not"} and set(value) == {"match"}:
        children = [value["match"]] if kind == "not" else value["match"]
        if not isinstance(children, list) or not children:
            raise BuildError("Logical condition requires operands")
        encoded = ",".join("(" + restore_condition(child, provider_by_url) + ")" for child in children)
        return f"{kind.upper()},({encoded})"
    if kind == "rule_set":
        provider = provider_by_url.get(value.get("match"))
        if provider is None or set(value) - {"match", "update_interval", "no_resolve"}:
            raise BuildError("Unexpected nested provider")
        if value.get("update_interval") != 86400:
            raise BuildError("Nested provider update interval changed")
        text = f"RULE-SET,{provider}"
        if "no_resolve" in value:
            if value["no_resolve"] is not True:
                raise BuildError("Invalid nested no_resolve")
            text += ",no-resolve"
        return text
    kinds = {"protocol": "NETWORK", "dest_port": "DST-PORT", "domain": "DOMAIN", "domain_suffix": "DOMAIN-SUFFIX"}
    if kind in kinds and set(value) == {"match"}:
        match = value["match"].upper() if kind == "protocol" else value["match"]
        return f"{kinds[kind]},{match}"
    raise BuildError(f"Unexpected logical matcher: {kind}")


def nested_rule_sets(wrapper: dict[str, Any]):
    kind, value = next(iter(wrapper.items()))
    if kind == "rule_set":
        yield value
    elif kind in {"and", "or"}:
        for child in value["match"]:
            yield from nested_rule_sets(child)
    elif kind == "not":
        yield from nested_rule_sets(value["match"])


def render_rules(
    model: dict[str, Any], provider_files: dict[str, list[str]]
) -> list[dict[str, Any]]:
    """Keep shared source order, with APNs first and Private Relay before Apple."""
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
    private_files = provider_files.get(PRIVATERELAY_PROVIDER, [])
    if private_files and private_files != [PRIVATERELAY_FILENAME]:
        raise BuildError("Expected one standalone Private Relay rule set")
    private_inserted = False
    for raw in model["rules"]:
        parts = split_rule(raw)
        kind = parts[0]
        if kind in {"AND", "OR", "NOT"} and len(parts) == 3:
            wrapper = render_condition(",".join(parts[:-1]), provider_files)
            item = wrapper[kind.lower()]
            item["policy"] = POLICY_ALIASES.get(parts[-1], parts[-1])
            if raw in model.get("quic_rules", []):
                item["name"] = "屏蔽国外 QUIC"
                item["disabled"] = False
            rules.append(wrapper)
        elif kind == "MATCH" and len(parts) == 2:
            rules.append({"default": {"policy": POLICY_ALIASES.get(parts[1], parts[1])}})
        elif kind == "RULE-SET" and (
            len(parts) == 3 or (len(parts) == 4 and parts[-1] == "no-resolve")
        ):
            provider = parts[1]
            if provider == "apple" and private_files and not private_inserted:
                rules.append({"rule_set": {
                    "match": f"{RAW_BASE}/dist/egern/{PRIVATERELAY_FILENAME}",
                    "policy": "Proxy", "name": PRIVATERELAY_PROVIDER,
                    "update_interval": 86400,
                }})
                private_inserted = True
            filenames = provider_files.get(provider)
            if not filenames or len(filenames) != 1:
                raise BuildError(f"Expected one native file for Mihomo provider: {provider}")
            no_resolve = len(parts) == 4
            item: dict[str, Any] = {
                "match": f"{RAW_BASE}/dist/egern/{filenames[0]}",
                "policy": POLICY_ALIASES.get(parts[2], parts[2]),
                "update_interval": 86400,
            }
            if no_resolve:
                item["no_resolve"] = True
            rules.append({"rule_set": item})
        elif kind == "DOMAIN-SUFFIX" and len(parts) == 3:
            rules.append({"domain_suffix": {"match": parts[1], "policy": POLICY_ALIASES.get(parts[2], parts[2])}})
        elif kind == "DOMAIN" and len(parts) == 3:
            rules.append({"domain": {"match": parts[1], "policy": POLICY_ALIASES.get(parts[2], parts[2])}})
        else:
            raise BuildError(f"Unsupported Mihomo rule: {raw}")
    if private_files and not private_inserted:
        raise BuildError("Standalone Private Relay requires the shared Apple anchor")
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
    shared_rules = rules[1:]
    private_files = provider_files.get(PRIVATERELAY_PROVIDER, [])
    if private_files:
        private_url = f"{RAW_BASE}/dist/egern/{PRIVATERELAY_FILENAME}"
        positions = [i for i, rule in enumerate(shared_rules)
                     if rule.get("rule_set", {}).get("match") == private_url]
        expected = {"rule_set": {
            "match": private_url, "policy": "Proxy", "name": PRIVATERELAY_PROVIDER,
            "update_interval": 86400,
        }}
        apple_files = provider_files.get("apple", [])
        if private_files != [PRIVATERELAY_FILENAME] or len(positions) != 1 or len(apple_files) != 1:
            raise BuildError("Expected one standalone Private Relay rule before Apple")
        index = positions[0]
        if (
            shared_rules[index] != expected or index + 1 >= len(shared_rules)
            or shared_rules[index + 1].get("rule_set", {}).get("match")
            != f"{RAW_BASE}/dist/egern/{apple_files[0]}"
        ):
            raise BuildError("Standalone Private Relay must use Proxy immediately before Apple")
        shared_rules = shared_rules[:index] + shared_rules[index + 1:]
    provider_by_url = {
        f"{RAW_BASE}/dist/egern/{filename}": provider
        for provider, filenames in provider_files.items()
        if provider not in {"apns", PRIVATERELAY_PROVIDER}
        for filename in filenames
    }
    actual: list[str] = []
    kinds = {"domain": "DOMAIN", "domain_suffix": "DOMAIN-SUFFIX"}
    for wrapper in shared_rules:
        if len(wrapper) != 1:
            raise BuildError("Routing rule must contain exactly one matcher")
        kind, item = next(iter(wrapper.items()))
        if kind in {"and", "or", "not"}:
            value = {key: value for key, value in item.items() if key not in {"policy", "name", "disabled"}}
            raw = restore_condition({kind: value}, provider_by_url) + "," + item["policy"]
            if raw in model.get("quic_rules", []):
                if set(item) != {"match", "policy", "name", "disabled"} or item.get("name") != "屏蔽国外 QUIC" or item.get("disabled") is not False:
                    raise BuildError("Generated foreign QUIC rule must start enabled")
            elif set(item) != {"match", "policy"}:
                raise BuildError("Unexpected logical rule attributes")
        elif kind == "rule_set":
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
    expected: list[str] = []
    for raw in model["rules"]:
        parts = split_rule(raw)
        policy_index = 1 if parts[0] == "MATCH" else len(parts) - 1 if parts[0] in {"AND", "OR", "NOT"} else 2
        parts[policy_index] = POLICY_ALIASES.get(parts[policy_index], parts[policy_index])
        expected.append(",".join(parts))
    if actual != expected:
        raise BuildError(
            "Egern routing differs from Mihomo in order, count, policy, or no-resolve; "
            "only the declared policy aliases and APNs/Private Relay additions are allowed"
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


def proxy_nameservers() -> list[str]:
    """Use the provider's private DNS from MESL.yaml (dns.nameserver).

    Public resolvers cannot replace the provider's node-domain resolution.
    This explicit Egern override must survive Mihomo DNS model updates.
    """
    return list(MESL_PROXY_NAMESERVERS)


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


def dns_policy_target(
    value: Any, provider: str, *, foreign_servers: list[str] | None = None
) -> str:
    values = value if isinstance(value, list) else [value]
    if foreign_servers and values == foreign_servers:
        return "Foreign"
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
        group = dns_policy_target(
            target, provider, foreign_servers=model.get("dns", {}).get("nameserver")
        )
        if group not in {"system", "Foreign"}:
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

    # DNS selection follows the source policy, independently of traffic routing.
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
                dns_policy_target(
                    target, provider, foreign_servers=model.get("dns", {}).get("nameserver")
                ),
            )

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
        proxy_group.get("flatten", False) is not False
        or proxy_group.get("policies", [])[:2] != ["订阅", "订阅2"]
        or "filter" in proxy_group
    ):
        raise BuildError("Proxy must retain selectable groups without flattening or a regional filter")
    known = set(names) | BUILTIN_POLICIES
    apns_files = provider_files.get("apns", [])
    if any(filename not in generated for filename in apns_files):
        raise BuildError("APNs native rule set was not generated")
    validate_rule_alignment(profile["rules"], model, provider_files)
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
    filtered_groups = {
        ("台湾" if entry["name"] == "台湾省" else entry["name"]): regex_text(entry)
        for entry in model["regions"]
    }
    filtered_groups.update({
        entry["name"]: rate_filter(entry) for entry in model["rateRegions"]
    })
    filtered_groups["其他节点"] = negative_filter([
        regex_text(entry) for entry in model["regions"]
    ])
    for name, pattern in filtered_groups.items():
        if name not in names:
            raise BuildError(f"Required filtered policy group is missing: {name}")
        group = groups[names.index(name)]
        if (
            group.get("policies") != ["订阅", "订阅2"]
            or group.get("flatten") is not True
            or group.get("filter") != pattern
        ):
            raise BuildError(f"{name} must filter both subscription groups")
    media_group = groups[names.index("媒体")] if "媒体" in names else {}
    for region in ("美国", "日本"):
        if media_group.get("policies", []).count(region) != 1:
            raise BuildError(f"媒体 must include the {region} policy group once")
    if media_group.get("flatten", False):
        raise BuildError("媒体 must retain selectable policy group references")
    for target in ("YouTube", "媒体", "PikPak", "Telegram"):
        if target not in names or "香港" not in groups[names.index(target)].get("policies", []):
            raise BuildError(f"{target} must include the Hong Kong policy group")
    if (
        "porn" not in names
        or groups[names.index("porn")].get("policies") != ["香港", "新加坡", "美国", "低倍率节点"]
        or groups[names.index("porn")].get("flatten", False)
    ):
        raise BuildError("porn must offer Hong Kong, Singapore, US, and low-rate groups without flattening nodes")
    if "EHentai" in names:
        group = groups[names.index("EHentai")]
        if group.get("flatten", False) or any(
            group.get("policies", []).count(choice) != 1
            for choice in ("美国", "新加坡", "低倍率节点")
        ):
            raise BuildError("EHentai must offer US, Singapore, and low-rate groups once")
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
        for reference in nested_rule_sets(wrapper):
            filename = reference["match"].rsplit("/", 1)[-1]
            if filename not in generated:
                raise BuildError(f"Rule references missing YAML file {filename}")
    if list(profile["rules"][-1]) != ["default"]:
        raise BuildError("Default rule must be last")
    dns = profile["dns"]
    if profile.get("block_quic") is not False:
        raise BuildError("Foreign QUIC logic requires global block_quic=false")
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
        raise BuildError("Mihomo nameserver-policy and default DNS were not preserved")
    if "apple_podcasts" in model["providers"]:
        if "Apple Podcasts" in names:
            raise BuildError("Apple Podcasts must route to 媒体 without a standalone group")
        podcast_rule = next(
            index for index, wrapper in enumerate(profile["rules"])
            if wrapper.get("rule_set", {}).get("match", "").endswith("/apple-podcasts.yaml")
        )
        cn_rule = next(
            index for index, wrapper in enumerate(profile["rules"])
            if wrapper.get("rule_set", {}).get("match", "").endswith("/apple-cn.yaml")
        )
        source_podcasts = next(i for i, raw in enumerate(model["rules"]) if raw.startswith("RULE-SET,apple_podcasts,"))
        source_cn = next(i for i, raw in enumerate(model["rules"]) if raw.startswith("RULE-SET,apple_cn,"))
        if (podcast_rule < cn_rule) != (source_podcasts < source_cn):
            raise BuildError("Apple Podcasts and Apple CN must retain source order")
    if dns.get("proxy_nameservers") != proxy_nameservers():
        raise BuildError("MESL private proxy nameservers were not preserved")
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
    egern_only = manifest.get("egern_only_rule_sets", [])
    if (
        not isinstance(egern_only, list)
        or any(not isinstance(record, dict) for record in egern_only)
        or [record.get("provider") for record in egern_only] not in ([], [PRIVATERELAY_PROVIDER])
    ):
        raise BuildError("Unsupported Egern-only rule manifest")
    for record in [*records, *egern_only]:
        name = record["provider"]
        if name == "apns":
            if (
                record.get("source_repository") != "ttyyss2233/Tool"
                or record.get("source_path") != "shadowrocket/rules/apns.list"
            ):
                raise BuildError("APNs rule manifest source changed")
        elif name == PRIVATERELAY_PROVIDER:
            if (
                record.get("egern_only") is not True
                or record.get("behavior") != "domain"
                or record.get("output") != f"dist/egern/{PRIVATERELAY_FILENAME}"
            ):
                raise BuildError("Invalid standalone Private Relay manifest")
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
        if name == PRIVATERELAY_PROVIDER and not set(rule) <= {"domain_set", "domain_suffix_set"}:
            raise BuildError("Standalone Private Relay must contain domain rules only")
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
    parser.add_argument("--dns-model", type=Path, required=True)
    parser.add_argument("--dns-mihomo-commit", required=True)
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
        # Rule artifacts remain pinned to their manifest; DNS follows its own
        # immutable Mihomo snapshot so converter publication cannot retain old DNS.
        dns_model = json.loads(args.dns_model.read_text(encoding="utf-8"))
        model = apply_dns_model(model, dns_model)
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
                "proxy_nameservers": proxy_nameservers(),
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
            "egern_only_rule_sets": manifest.get("egern_only_rule_sets", []),
            "foreign_quic": {
                "source_rules": model.get("quic_rules", []),
                "source_default": model.get("options", {}).get("屏蔽国外QUIC"),
                "global_block_quic": False,
                "toggle": "rules[].and.disabled",
                "enabled_by_default": any(raw in model["rules"] for raw in model.get("quic_rules", [])),
            },
            "routing_alignment": {
                "exceptions": ["apns-first", "privaterelay-before-apple"],
                "policy_aliases": POLICY_ALIASES,
                "privaterelay_rules": 1,
                "apns_rules": 1,
                "mihomo_rules": model["rules"],
                "shared_rule_count": len(model["rules"]),
            },
            "group_filters": filters,
            "dns": {
                "mihomo_script": {"repository": MIHOMO_REPO, "commit": args.dns_mihomo_commit},
                "bootstrap": profile["dns"]["bootstrap"],
                "forward_rules": len(profile["dns"]["forward"]),
                "upstreams": profile["dns"]["upstreams"],
                "proxy_nameservers": profile["dns"]["proxy_nameservers"],
                "proxy_nameservers_source": {
                    "reference_file": "MESL.yaml",
                    "reference_field": "dns.nameserver",
                    "overrides": "Mihomo proxy-server-nameserver",
                },
            },
            "subscription": {
                "group": "订阅",
                "default_subscription_group": profile["default_subscription_group"],
                "default_proxy_group": profile["default_proxy_group"],
                "urls_published": False,
                "reason": "Default group names are public; subscription credentials remain local.",
            },
            "migration_boundaries": [
                "APNs traffic is first with Proxy; standalone Private Relay uses Proxy immediately before the shared Apple rule.",
                "All shared routing rules preserve Mihomo source order, duplicates, and no-resolve flags; target policies use the declared Egern mappings, including Apple Podcasts to 媒体.",
                "Private, MCDN, Claude/AI, Steam, and all other providers have no Egern-specific reordering; policy mappings are pron to porn and Apple Podcasts to 媒体.",
                "The independent converter Private Relay artifact is verified and retained as an Egern-only rule.",
                "The Egern policy group is named porn; source pron targets and group references map to porn, offering Hong Kong, Singapore, US, and low-rate choices. EHentai adds US, Singapore, and low-rate choices; the low-rate filter also matches 实验.",
                "Mihomo IPv4/IPv6 preferred DIRECT pseudo-proxies map to Egern DIRECT.",
                "Mihomo default-nameserver IPs retain their order as plain-UDP Egern bootstrap.",
                "The two legacy excluded DoH endpoint suffixes retain upstream URLs without injected routing; any new suffix fails explicitly.",
                "Only Mihomo nameserver-policy entries become ordered DNS Forward rules, followed by the default foreign nameservers; no APNs, Podcasts, or static Direct DNS overrides are synthesized.",
                "Source DNS server order and duplicates remain intact for shared DNS; proxy_nameservers explicitly uses the two private DoH endpoints from MESL.yaml dns.nameserver in reference order.",
                "Egern cannot reproduce Mihomo runtime direct-nameserver re-resolution after a policy-group selection changes.",
                "Real-IP exclusions, AliDNS host additions, Flower aliases, and subscription defaults remain explicit Egern settings.",
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
