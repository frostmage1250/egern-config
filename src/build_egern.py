#!/usr/bin/env python3
"""Translate one published upstream-aligned Mihomo script into native Egern YAML."""

from __future__ import annotations

import argparse
import ipaddress
import json
import math
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

ROOT = Path(__file__).resolve().parents[1]
CUSTOM = json.loads((ROOT / "custom/customizations.json").read_text(encoding="utf-8"))
SOURCE = CUSTOM["rule_source"]
RAW_BASE = f'https://raw.githubusercontent.com/{SOURCE["repository"]}/{SOURCE["branch"]}'
RULE_BASE = f'{RAW_BASE}/{SOURCE["directory"]}'
INTERVAL = SOURCE["update_interval"]


class BuildError(RuntimeError):
    pass


def policy_target(value):
    # The two Mihomo-only rule actions have no native Egern counterpart.
    if value in {"REJECT-DROP", "PASS"}:
        raise BuildError(f"Unsupported Egern rule action: {value}")
    custom = CUSTOM.get("groups", {})
    if value in custom.get("remove", []):
        return "DIRECT"
    return custom.get("aliases", {}).get(value, value)


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
            "match": f"{RULE_BASE}/{files[0]}", "update_interval": INTERVAL,
        }
        if len(parts) == 3:
            value["no_resolve"] = True
        return {"rule_set": value}
    kinds = {"NETWORK": "protocol", "DST-PORT": "dest_port", "DOMAIN": "domain", "DOMAIN-SUFFIX": "domain_suffix"}
    if kind in kinds and len(parts) == 2:
        value = parts[1].lower() if kind == "NETWORK" else parts[1]
        return {kinds[kind]: {"match": value}}
    raise BuildError(f"Unsupported logical condition: {text}")





def render_policy_groups(model):
    definitions = [*model["regions"], *model["rateRegions"], *model.get("homeRegions", [])]
    patterns = {entry["name"]: regex_text(entry) for entry in definitions}
    for name, addition in CUSTOM.get("groups", {}).get("filter_append", {}).items():
        if name in patterns:
            patterns[name] += "|" + addition
    patterns["其他节点"] = negative_filter([regex_text(entry) for entry in model["regions"]])
    excluded = []
    if model["options"].get("过滤非地区节点"):
        excluded.append(regex_text(model["excludeFilter"]))
    for option, field in [("过滤低倍率节点", "lowRateRegionName"), ("过滤高倍率节点", "highRateRegionName")]:
        if model["options"].get(option) and model.get(field) in patterns:
            excluded.append(patterns[model[field]])
    source_filter = negative_filter(excluded)
    templates = set(model["template_node_names"])
    direct_names = {proxy["name"] for proxy in model["direct_proxies"]}
    services = {entry["name"]: entry for entry in model["services"]}
    manual = next((group["name"] for group in model["groups"]
                   if services.get(group["name"], {}).get("includeAll") and group["type"] == "select"), None)
    if manual is None:
        raise BuildError("Upstream needs a manual node group to host an Egern subscription")
    extra_subscriptions = CUSTOM.get("groups", {}).get("extra_subscriptions", [])
    source_names = {group["name"] for group in model["groups"]}
    if len(extra_subscriptions) != len(set(extra_subscriptions)) or source_names.intersection(extra_subscriptions):
        raise BuildError("Extra subscription names must be unique and absent from source groups")
    subscriptions = [manual, *extra_subscriptions]
    result = []
    for group in model["groups"]:
        kind = {"select": "select", "url-test": "auto_test", "load-balance": "load_balance"}.get(group["type"])
        if kind is None:
            raise BuildError(f'Unsupported upstream policy group type: {group["type"]}')
        name = group["name"]
        item = {"name": name}
        for key in ("icon", "hidden"):
            if key in group and (key != "icon" or CUSTOM.get("icons", {}).get("enabled", True)):
                item[key] = group[key]
        if group.get("url"):
            item["latency_test_url"] = group["url"]
        if kind == "auto_test":
            for key in ("interval", "tolerance"):
                if key in group:
                    item[key] = group[key]
            if "timeout" in group:
                item["timeout"] = max(1, min(60, math.ceil(group["timeout"] / 1000)))
        elif kind == "load_balance":
            # Native destination hashing is the closest supported sticky-session strategy.
            item["algorithm"] = "round_robin" if group.get("strategy") == "round-robin" else "hash"
        if name == manual:
            item.update({"policies": [], "urls": [], "filter": source_filter})
            result.append({kind: item})
            for subscription in extra_subscriptions:
                result.append({"select": {**item, "name": subscription, "policies": [], "urls": []}})
            continue
        choices = []
        dynamic = False
        for choice in group.get("proxies", []):
            if choice in templates:
                dynamic = True
                for subscription in subscriptions:
                    if subscription not in choices:
                        choices.append(subscription)
            elif choice == manual:
                choices.extend(subscriptions)
            elif choice in direct_names:
                choices.append("DIRECT")
            elif choice not in {"REJECT-DROP", "PASS"}:
                choices.append(choice)
        item["policies"] = list(dict.fromkeys(choices)) or ["DIRECT"]
        if dynamic:
            item["flatten"] = True
            pattern_name = name.removesuffix("-自动选择")
            item["filter"] = patterns.get(pattern_name, source_filter)
        result.append({kind: item})
    removed = set(CUSTOM.get("groups", {}).get("remove", []))
    result = [wrapper for wrapper in result if next(iter(wrapper.values()))["name"] not in removed]
    for wrapper in result:
        item = next(iter(wrapper.values()))
        item["name"] = policy_target(item["name"])
        item["policies"] = list(dict.fromkeys(policy_target(choice) for choice in item["policies"]))
    apply_group_customizations(result)
    return result, policy_target(manual)


def apply_group_customizations(groups):
    custom = CUSTOM.get("groups", {})
    removed = set(custom.get("remove_candidates", []))
    for wrapper in groups:
        item = next(iter(wrapper.values()))
        name = item["name"]
        choices = list(item["policies"])
        front = custom.get("prepend", {}).get(name, [])
        choices = front + [choice for choice in choices if choice not in front]
        if name in custom.get("replace", {}):
            choices = list(custom["replace"][name])
        else:
            choices.extend(custom.get("append", {}).get(name, []))
        item["policies"] = list(dict.fromkeys(choice for choice in choices if choice not in removed))
        if name in custom.get("flatten", {}):
            item["flatten"] = custom["flatten"][name]


def rule_reference(provider, files, **attributes):
    filename = files.get(provider)
    if not filename:
        raise BuildError(f"Missing converted provider: {provider}")
    return {"rule_set": {
        "match": f"{RULE_BASE}/{filename[0]}",
        "update_interval": INTERVAL, **attributes,
    }}


def render_rules(model, files):
    result = render_dns_endpoint_rules(model)
    extras = [CUSTOM["routing"][name] for name in ("apns", "privaterelay")]
    inserted = set()
    omitted = set(model.get("quic_rules", [])) if CUSTOM["routing"].get("omit_foreign_quic") else set()
    for raw in model["rules"]:
        if raw in omitted:
            continue
        parts = split_rule(raw)
        kind = parts[0]
        if kind == "RULE-SET":
            attributes = {"policy": policy_target(parts[2])}
            if parts[3:] == ["no-resolve"]:
                attributes["no_resolve"] = True
            elif parts[3:]:
                raise BuildError(f"Unsupported rule flags: {raw}")
            result.append(rule_reference(parts[1], files, **attributes))
            for extra in extras:
                if parts[1] == extra["after_provider"]:
                    attributes = {"policy": policy_target(extra["policy"])}
                    if extra.get("no_resolve"):
                        attributes["no_resolve"] = True
                    result.append(rule_reference(extra["provider"], files, **attributes))
                    inserted.add(extra["provider"])
        elif kind == "MATCH" and len(parts) == 2:
            result.append({"default": {"policy": policy_target(parts[1])}})
        elif kind in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX", "IP-CIDR", "IP-CIDR6", "GEOIP", "IP-ASN"}:
            field = {"DOMAIN": "domain", "DOMAIN-SUFFIX": "domain_suffix", "DOMAIN-KEYWORD": "domain_keyword",
                     "DOMAIN-REGEX": "domain_regex", "IP-CIDR": "ip_cidr", "IP-CIDR6": "ip_cidr6",
                     "GEOIP": "geoip", "IP-ASN": "asn"}[kind]
            item = {"match": parts[1], "policy": policy_target(parts[2])}
            if parts[3:] == ["no-resolve"]:
                item["no_resolve"] = True
            elif parts[3:]:
                raise BuildError(f"Unsupported rule flags: {raw}")
            result.append({field: item})
        elif kind == "PROCESS-NAME":
            # Egern on iOS exposes no process-name matcher; domain rules remain active.
            continue
        elif kind in {"AND", "OR", "NOT"} and len(parts) == 3:
            condition = render_condition(",".join(parts[:-1]), files)
            condition[kind.lower()]["policy"] = policy_target(parts[-1])
            result.append(condition)
        else:
            raise BuildError(f"Unsupported source rule: {raw}")
    if inserted != {extra["provider"] for extra in extras}:
        raise BuildError("An APNs or Private Relay placement anchor is missing")
    placement = CUSTOM["routing"].get("mcdn")
    if placement:
        blocking = rule_reference(placement["provider"], files, policy="REJECT")
        apns = CUSTOM["routing"]["apns"]
        apns_rule = rule_reference(apns["provider"], files,
                                   policy=policy_target(apns["policy"]), no_resolve=apns["no_resolve"])
        anchor = rule_reference(placement["before_provider"], files)["rule_set"]["match"]
        if result.count(blocking) != 1 or result.count(apns_rule) != 1:
            raise BuildError("MCDN/APNs placement requires one rule each")
        result.remove(blocking)
        result.remove(apns_rule)
        positions = [i for i, rule in enumerate(result) if rule.get("rule_set", {}).get("match") == anchor]
        if len(positions) != 1:
            raise BuildError("MCDN placement anchor must be unique")
        result[positions[0]:positions[0]] = [blocking, apns_rule]
    return result


def nameservers(model):
    result = []
    for value in model["dns"]["nameserver"]:
        server, _ = split_nameserver_policy(value)
        result.append(server)
    if not result:
        raise BuildError("Mihomo DNS model contains no nameservers")
    return result


def render_dns_endpoint_rules(model):
    result = []
    seen = {}
    values = list(model["dns"].get("nameserver", []))
    for servers in model["dns"].get("nameserver-policy", {}).values():
        values.extend(servers if isinstance(servers, list) else [servers])
    for value in values:
        server, suffix = split_nameserver_policy(value)
        if not suffix:
            continue
        target = policy_target(suffix.split("&", 1)[0])
        host = urlsplit(server).hostname if "://" in server else server
        if not host or host in {"system", "system://"}:
            continue
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            kind, match = "domain", host
        else:
            kind, match = ("ip_cidr6" if address.version == 6 else "ip_cidr"), str(address) + ("/128" if address.version == 6 else "/32")
        if (kind, match) in seen and seen[kind, match] != target:
            raise BuildError(f"Conflicting DNS endpoint route: {host}")
        if (kind, match) not in seen:
            result.append({kind: {"match": match, "policy": target}})
            seen[kind, match] = target
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



def render_dns_forward(model, files):
    forward = []
    for key, target in model["dns"].get("nameserver-policy", {}).items():
        if not key.startswith("rule-set:"):
            raise BuildError(f"Unsupported DNS policy: {key}")
        provider = key.removeprefix("rule-set:")
        forward.append({"proxy_rule_set": {
            "match": f"{RULE_BASE}/{files[provider][0]}",
            "update_interval": INTERVAL,
            "value": dns_policy_target(target, provider, foreign_servers=model["dns"]["nameserver"]),
        }})
    forward.append({"domain_wildcard": {"match": "*", "value": "Foreign"}})
    return forward


def hosts(model):
    result = {}
    for pattern, value in model["hosts"].items():
        # Egern uses globs; Mihomo +. matches both the apex and its subdomains.
        if pattern.startswith("+."):
            result[pattern[2:]] = value
            result["*" + pattern[1:]] = value
        elif pattern.startswith("."):
            result["*" + pattern] = value
        else:
            result[pattern] = value
    result.update(CUSTOM.get("dns", {}).get("hosts_override", {}))
    return result


def provider_files(model, index):
    files = {}
    names = []
    for rule in model["rules"]:
        names.extend(re.findall(r"\bRULE-SET,([^,()]+)", rule))
    names.extend(key.removeprefix("rule-set:") for key in model["dns"].get("nameserver-policy", {}))
    for name in dict.fromkeys(names):
        source = model["providers"][name]
        record = index["providers"].get(name)
        if not record or any(record.get(key) != source.get(key, "yaml" if key == "format" else None)
                             for key in ("url", "behavior", "format")):
            raise BuildError(f"Native provider needs conversion before profile publication: {name}")
        filename = record["file"]
        if not re.fullmatch(r"[a-z0-9.-]+\.yaml", filename):
            raise BuildError(f"Invalid native filename: {filename}")
        files[name] = [filename]
    for item in (CUSTOM["routing"][name] for name in ("apns", "privaterelay")):
        filename = item["provider"] + ".yaml"
        if filename not in index["extra_files"]:
            raise BuildError(f"Missing retained Egern rule: {filename}")
        files[item["provider"]] = [filename]
    return files


def validate_profile(profile, model):
    groups = [next(iter(wrapper.values())) for wrapper in profile["policy_groups"]]
    names = [group["name"] for group in groups]
    if len(names) != len(set(names)):
        raise BuildError("Duplicate policy group")
    expected_names = []
    subscription = profile["default_subscription_group"]
    extras = CUSTOM.get("groups", {}).get("extra_subscriptions", [])
    removed = set(CUSTOM.get("groups", {}).get("remove", []))
    for group in model["groups"]:
        if group["name"] in removed:
            continue
        name = policy_target(group["name"])
        expected_names.append(name)
        if name == subscription:
            expected_names.extend(extras)
    if names != expected_names:
        raise BuildError("Native group order must match the source plus explicit subscriptions")
    for name in [subscription, *extras]:
        group = next(item for item in groups if item["name"] == name)
        if group["policies"] or group["urls"] or "update_interval" in group:
            raise BuildError("Public subscriptions must start empty without an update interval")
    for field in ("default_subscription_group", "default_proxy_group"):
        if profile[field] not in names:
            raise BuildError("Default group is undefined: " + field)
    excluded = set(CUSTOM.get("services", {}).get("exclude", []))
    if excluded.intersection(names):
        raise BuildError("Excluded service group remains in the profile")
    if CUSTOM.get("latency_tests", {}).get("enabled", True) is False:
        if any(next(iter(wrapper)) in {"auto_test", "fallback"} for wrapper in profile["policy_groups"]):
            raise BuildError("Latency-based group remains in the profile")
        forbidden = {"latency_test_url", "interval", "timeout", "tolerance"}
        if any(forbidden.intersection(group) for group in groups):
            raise BuildError("Latency-test fields remain in the profile")
    if CUSTOM.get("icons", {}).get("enabled", True) is False:
        if any("icon" in group for group in groups):
            raise BuildError("Policy group icons remain in the profile")
    known = set(names) | {"DIRECT", "REJECT"}
    for group in groups:
        if any(policy not in known for policy in group["policies"]):
            raise BuildError(f'Undefined policy in {group["name"]}')
    for wrapper in profile["rules"]:
        item = next(iter(wrapper.values()))
        if item["policy"] not in known:
            raise BuildError(f'Undefined rule policy: {item["policy"]}')
    if list(profile["rules"][-1]) != ["default"]:
        raise BuildError("Default rule must be last")


def render_dns_hijack(source):
    """Translate paired Mihomo UDP/TCP wildcard targets to Egern address patterns."""
    by_port = {}
    for value in source.get("tun", {}).get("dns-hijack", []):
        if not isinstance(value, str):
            raise BuildError("DNS hijack entries must be strings")
        match = re.fullmatch(r"(?:(tcp|udp)://)?any:([0-9]+)", value)
        if not match:
            raise BuildError("DNS hijack target requires an explicit Egern adaptation: " + value)
        port = int(match[2])
        if not 1 <= port <= 65535:
            raise BuildError("Invalid DNS hijack port: " + value)
        by_port.setdefault(port, set()).add(match[1] or "udp")
    for port, protocols in by_port.items():
        if protocols != {"tcp", "udp"}:
            raise BuildError("Cannot preserve a protocol-only DNS hijack target: " + str(port))
    return [f"*:{port}" for port in by_port]


def remove_latency_settings(profile):
    if CUSTOM.get("latency_tests", {}).get("enabled", True):
        return
    for field in ("proxy_latency_test_url", "direct_latency_test_url", "proxy_latency_test_timeout", "direct_latency_test_timeout"):
        profile.pop(field, None)
    for wrapper in profile["policy_groups"]:
        item = next(iter(wrapper.values()))
        for field in ("latency_test_url", "interval", "timeout", "tolerance"):
            item.pop(field, None)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--index", type=Path, required=True)
    args = parser.parse_args()
    model = json.loads(args.model.read_text(encoding="utf-8"))
    index = json.loads(args.index.read_text(encoding="utf-8"))
    files = provider_files(model, index)
    groups, subscription = render_policy_groups(model)
    source = model["globals"]
    # Egern-only tunnel capture is needed for the retained APNs route.
    profile = {
        "ipv6": source.get("ipv6", False),
        "allow_external_connections": source.get("allow-lan", False),
        "vif_only": bool(source.get("tun", {}).get("enable", False)),
        "include_all_networks": True,
        "include_apns": True,
        "block_quic": False,
        "default_subscription_group": subscription,
        "default_proxy_group": policy_target("默认代理"),
        "dns": {
            "bootstrap": bootstrap_nameservers(model),
            "upstreams": render_dns_upstreams(model),
            "forward": render_dns_forward(model, files),
            "hosts": hosts(model),
            "proxy_nameservers": CUSTOM.get("dns", {}).get("proxy_nameservers", [split_nameserver_policy(value)[0] for value in model["dns"].get("proxy-server-nameserver", [])]),
        },
        "policy_groups": groups,
        "rules": render_rules(model, files),
    }
    profile.update(CUSTOM.get("profile", {}))
    # Preserve source destination ports using Egern's wildcard address notation.
    hijack = render_dns_hijack(source)
    if hijack:
        profile["hijack_dns"] = hijack
    else:
        profile.pop("hijack_dns", None)
    # Merge literal source exceptions with the explicit Egern real-IP list.
    literals = [value for value in model["dns"].get("fake-ip-filter", []) if not value.startswith("rule-set:")]
    real_ip_domains = list(dict.fromkeys([*literals, *CUSTOM.get("real_ip_domains", [])]))
    if real_ip_domains:
        profile["real_ip_domains"] = real_ip_domains
    remove_latency_settings(profile)
    validate_profile(profile, model)
    (ROOT / "Profile.yaml").write_text(yaml.safe_dump(profile, allow_unicode=True, sort_keys=False, width=1000), encoding="utf-8")
    print(f'Published {len(groups)} native policy groups and {len(profile["rules"])} rules.')


if __name__ == "__main__":
    main()
