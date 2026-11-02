#!/usr/bin/env python3
"""Read an independently extracted Mihomo snapshot and apply the Egern manifest."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import ipaddress
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
    # Source Direct is a selectable Mihomo strategy; Egern uses its built-in action.
    return "DIRECT" if value == "Direct" else value


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
    patterns = {entry["name"]: regex_text(entry) for entry in model["regions"]}
    for entry in [*model["rateRegions"], *model.get("homeRegions", [])]:
        pattern = regex_text(entry)
        addition = CUSTOM["groups"]["filter_append"].get(entry["name"])
        patterns[entry["name"]] = pattern + "|" + addition if addition else pattern
    excluded = []
    if model["options"].get("过滤非地区节点"):
        excluded.append(regex_text(model["excludeFilter"]))
    for option, key, default in [
        ("过滤低倍率节点", "lowRateRegionName", "低倍率节点"),
        ("过滤高倍率节点", "highRateRegionName", "高倍率节点"),
    ]:
        if model["options"].get(option):
            name = model.get(key, default)
            if name in patterns:
                excluded.append(patterns[name])
    patterns["其他节点"] = negative_filter([regex_text(entry) for entry in model["regions"]])
    groups = []
    subscriptions = CUSTOM["subscriptions"]
    if any(group["name"] in subscriptions[1:] for group in model["groups"]):
        raise BuildError("Source group collides with a local subscription")
    for group in model["groups"]:
        name = group["name"]
        if name in CUSTOM["groups"]["remove"]:
            continue
        if name == subscriptions[0]:
            for subscription in subscriptions:
                groups.append({"select": {
                    "name": subscription, "policies": [], "urls": [],
                    "filter": negative_filter(excluded),
                }})
            continue
        if name in patterns:
            groups.append({"select": {
                "name": name, "policies": subscriptions,
                "flatten": True, "filter": patterns[name],
            }})
            continue
        choices = [policy_target(choice) for choice in group.get("proxies", [])
                   if not choice.startswith("__") and choice not in CUSTOM["groups"]["remove_candidates"]]
        if name == "Proxy":
            front = CUSTOM["groups"]["subscription_front"]
            choices = front + [choice for choice in choices if choice not in front]
        if name in CUSTOM["groups"]["replace"]:
            choices = CUSTOM["groups"]["replace"][name]
        else:
            choices += CUSTOM["groups"]["append"].get(name, [])
        item = {"name": name, "policies": list(dict.fromkeys(choices)) or ["DIRECT"]}
        if name == "Proxy":
            item["flatten"] = False
        groups.append({"select": item})
    return groups


def rule_reference(provider, files, **attributes):
    filenames = files.get(provider, [])
    if len(filenames) != 1:
        raise BuildError(f"Missing converted provider: {provider}")
    return {"rule_set": {
        "match": f"{RULE_BASE}/{filenames[0]}",
        "update_interval": INTERVAL, **attributes,
    }}


def render_rules(model, files):
    result = render_dns_endpoint_rules(model)
    omitted = set(model["quic_rules"]) if CUSTOM["routing"]["omit_foreign_quic"] else set()
    apns = CUSTOM["routing"]["apns"]
    private = CUSTOM["routing"]["privaterelay"]
    shared = [rule for rule in model["rules"] if rule not in omitted]
    blocking = [i for i, raw in enumerate(shared)
                if raw.startswith("RULE-SET," + apns["after_provider"] + ",")]
    if not blocking:
        raise BuildError("APNs blocking-stage anchor is missing")
    for index, raw in enumerate(shared):
        parts = split_rule(raw)
        kind = parts[0]
        if kind == "RULE-SET":
            provider = parts[1]
            if provider == private["before_provider"]:
                result.append(rule_reference(private["provider"], files, policy=private["policy"], name=private["provider"]))
            attributes = {"policy": policy_target(parts[2])}
            if parts[3:] == ["no-resolve"]:
                attributes["no_resolve"] = True
            elif parts[3:]:
                raise BuildError(f"Unsupported rule flags: {raw}")
            result.append(rule_reference(provider, files, **attributes))
        elif kind == "MATCH" and len(parts) == 2:
            result.append({"default": {"policy": policy_target(parts[1])}})
        elif kind in {"DOMAIN", "DOMAIN-SUFFIX"} and len(parts) == 3:
            field = {"DOMAIN": "domain", "DOMAIN-SUFFIX": "domain_suffix"}[kind]
            result.append({field: {"match": parts[1], "policy": policy_target(parts[2])}})
        elif kind in {"AND", "OR", "NOT"} and len(parts) == 3:
            condition = render_condition(",".join(parts[:-1]), files)
            condition[kind.lower()]["policy"] = policy_target(parts[-1])
            result.append(condition)
        else:
            raise BuildError(f"Unsupported source rule: {raw}")
        if index == max(blocking):
            result.append(rule_reference(apns["provider"], files, policy=apns["policy"], no_resolve=apns["no_resolve"]))
    if not any(raw.startswith("RULE-SET," + private["before_provider"] + ",") for raw in shared):
        raise BuildError("Private Relay Apple anchor is missing")
    return result


def nameservers(model: dict[str, Any]) -> list[str]:
    result: list[str] = []
    for value in model.get("dns", {}).get("nameserver", []):
        if not isinstance(value, str):
            continue
        server, policy = split_nameserver_policy(value)
        if policy is not None and (
            policy != "Proxy"
        ):
            raise BuildError(
                f"Unsupported DNS routing suffix outside the foreign DoH Proxy mapping: {value!r}"
            )
        result.append(server)
    if not result:
        raise BuildError("Mihomo DNS model contains no nameservers")
    return result


def render_dns_endpoint_rules(model: dict[str, Any]) -> list[dict[str, Any]]:
    """Translate the two foreign DoH #Proxy bindings into Egern domain routes."""
    nameservers_model = model.get("dns", {}).get("nameserver", [])
    if not nameservers_model:
        return []
    nameservers(model)  # Reject suffixes that cannot be translated safely.
    rules: list[dict[str, Any]] = []
    seen: set[str] = set()
    for value in nameservers_model:
        if not isinstance(value, str):
            continue
        server, policy = split_nameserver_policy(value)
        hostname = urlsplit(server).hostname
        if policy == "Proxy" and hostname not in seen:
            rules.append({"domain": {"match": hostname, "policy": "Proxy"}})
            seen.add(hostname)
    return rules


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


def render_direct_dns_forward(
    model: dict[str, Any],
    providers: dict[str, Any],
    provider_files: dict[str, list[str]],
) -> list[dict[str, Any]]:
    """Use system DNS for the fixed DIRECT domain prefix before business rules."""
    forward: list[dict[str, Any]] = []
    passed_direct_prefix = False
    for raw in model.get("rules", []):
        parts = split_rule(raw)
        kind = parts[0]
        policy = parts[-1] if kind in {"AND", "OR", "NOT", "MATCH"} else parts[2]
        if policy_target(policy) != "DIRECT":
            passed_direct_prefix = True
            continue
        if kind == "RULE-SET":
            provider = parts[1]
            definition = providers.get(provider)
            if definition is None:
                raise BuildError(f"Fixed DIRECT DNS provider is missing: {provider}")
            if definition.get("behavior") == "ipcidr":
                continue  # An IP match cannot select DNS before resolution.
            if definition.get("behavior") != "domain":
                raise BuildError(f"Fixed DIRECT DNS requires a domain provider: {provider}")
            filenames = provider_files.get(provider)
            if not filenames:
                raise BuildError(f"Fixed DIRECT DNS provider was not generated: {provider}")
            entries = [{"proxy_rule_set": {
                "match": f"{RULE_BASE}/{filename}",
                "value": CUSTOM["dns"]["fixed_direct_domains"], "update_interval": INTERVAL,
            }} for filename in filenames]
        elif kind in {"DOMAIN", "DOMAIN-SUFFIX"}:
            matcher = {"DOMAIN": "domain", "DOMAIN-SUFFIX": "domain_suffix"}[kind]
            entries = [{matcher: {"match": parts[1], "value": CUSTOM["dns"]["fixed_direct_domains"]}}]
        elif kind in {"IP-CIDR", "IP-CIDR6", "GEOIP"}:
            continue
        else:
            raise BuildError(f"Unsupported fixed DIRECT DNS rule: {raw}")
        if passed_direct_prefix:
            raise BuildError(f"Fixed DIRECT DNS domain rule must precede business rules: {raw}")
        forward.extend(entries)
    return forward


def render_dns_forward(
    model: dict[str, Any],
    providers: dict[str, Any],
    provider_files: dict[str, list[str]],
) -> list[dict[str, Any]]:
    forward = render_direct_dns_forward(model, providers, provider_files)

    def add(kind: str, match: str, value: str) -> None:
        item: dict[str, Any] = {"match": match, "value": value}
        if kind == "proxy_rule_set":
            item["update_interval"] = INTERVAL
        forward.append({kind: item})

    # Fixed DIRECT domains override the shared DNS policy; all other domains retain it.
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
                f"{RULE_BASE}/{filename}",
                dns_policy_target(
                    target, provider, foreign_servers=model.get("dns", {}).get("nameserver")
                ),
            )

    add("domain_wildcard", "*", "Foreign")
    return forward




def hosts(model):
    result = json.loads(json.dumps(model["hosts"]))
    for domain, additions in CUSTOM["dns"]["hosts_add_ips"].items():
        existing = result.get(domain, [])
        if not isinstance(existing, list):
            raise BuildError(f"Expected IP list for {domain}")
        result[domain] = existing + [value for value in additions if value not in existing]
    result.update(CUSTOM["dns"]["hosts_override"])
    return result


def provider_files(model, index):
    files = {}
    omitted = set(model["quic_rules"]) if CUSTOM["routing"]["omit_foreign_quic"] else set()
    names = []
    for rule in model["rules"]:
        if rule not in omitted:
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
    for item in ("apns", "privaterelay"):
        filename = item + ".yaml"
        if filename not in index["extra_files"]:
            raise BuildError(f"Missing extra rule file: {filename}")
        files[item] = [filename]
    return files


def validate_profile(profile):
    groups = [item["select"] for item in profile["policy_groups"]]
    names = [item["name"] for item in groups]
    if len(names) != len(set(names)):
        raise BuildError("Duplicate policy group")
    known = set(names) | {"DIRECT", "REJECT", "PASS"}
    for group in groups:
        if any(policy not in known for policy in group["policies"]):
            raise BuildError(f"Undefined policy in {group['name']}")
    for wrapper in profile["rules"]:
        item = next(iter(wrapper.values()))
        if item["policy"] not in known:
            raise BuildError(f"Undefined rule policy: {item['policy']}")
    if list(profile["rules"][-1]) != ["default"]:
        raise BuildError("Default rule must be last")
    for name in CUSTOM["subscriptions"]:
        group = next(item for item in groups if item["name"] == name)
        if group["policies"] or group["urls"] or "update_interval" in group:
            raise BuildError("Public subscriptions must start empty without an update interval")
    if "Direct" in names or profile["block_quic"]:
        raise BuildError("Unexpected Direct group or global QUIC block")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--index", type=Path, required=True)
    args = parser.parse_args()
    model = json.loads(args.model.read_text(encoding="utf-8"))
    index = json.loads(args.index.read_text(encoding="utf-8"))
    files = provider_files(model, index)
    if CUSTOM["dns"]["bootstrap"] != "source-ips-as-udp" or CUSTOM["dns"]["direct_reresolution"] != "fixed-direct-prefix-only" or CUSTOM["dns"]["proxy_binding"] != "domain-routes":
        raise BuildError("Unsupported DNS adaptation selection")
    profile = {
        **CUSTOM["profile"],
        "real_ip_domains": CUSTOM["real_ip_domains"],
        "dns": {
            "bootstrap": bootstrap_nameservers(model),
            "upstreams": render_dns_upstreams(model),
            "forward": render_dns_forward(model, model["providers"], files),
            "hosts": hosts(model),
            "proxy_nameservers": CUSTOM["dns"]["proxy_nameservers"],
        },
        "policy_groups": render_policy_groups(model),
        "rules": render_rules(model, files),
    }
    validate_profile(profile)
    text = yaml.safe_dump(profile, allow_unicode=True, sort_keys=False, width=1000)
    (ROOT / "Profile.yaml").write_text(text, encoding="utf-8")
    print(f"Generated {len(profile['policy_groups'])} groups and {len(profile['rules'])} rules.")


if __name__ == "__main__":
    main()
