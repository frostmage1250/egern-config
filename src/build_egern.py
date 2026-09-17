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
from urllib.parse import urlsplit
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
RULE_DIR = ROOT / "rules"
PROFILE_PATH = ROOT / "Profile.yaml"
REPORT_PATH = ROOT / "reports" / "source.json"
RAW_BASE = "https://raw.githubusercontent.com/frostmage1250/egern-config/main"
MIHOMO_REPO = "frostmage1250/mihomo-script"
BETT_REPO = "appshubcc/bett-rules"
CONVERTER_REPO = "frostmage1250/proxy-rules-converter"
CONVERTER_GEOLOCATION_LIST_PATH = "dist/mihomo/geolocation-cn.list"
CONVERTER_GEOLOCATION_REPORT_PATH = "reports/geolocation-cn.json"
APNS_REPO = "ttyyss2233/Tool"
APNS_PATH = "shadowrocket/rules/apns.list"
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


def resolve_provider_source(
    provider: dict[str, Any],
    *,
    bett_commit: str,
    converter_commit: str,
) -> dict[str, str]:
    provider_url = provider.get("url")
    if not isinstance(provider_url, str) or not provider_url:
        raise BuildError(f"Provider has no final URL: {provider}")

    parsed = urlsplit(provider_url)
    repository: str
    ref: str
    mrs_path: str
    if parsed.netloc == "fastly.jsdelivr.net":
        match = re.fullmatch(
            r"/gh/([^/]+/[^/@]+)@([^/]+)/(.+)\.mrs",
            parsed.path,
        )
        if not match:
            raise BuildError(f"Unsupported jsDelivr provider URL: {provider_url}")
        repository, ref, mrs_path = match.groups()
    elif parsed.netloc == "raw.githubusercontent.com":
        match = re.fullmatch(
            r"/([^/]+/[^/]+)/([^/]+)/(.+)\.mrs",
            parsed.path,
        )
        if not match:
            raise BuildError(f"Unsupported raw GitHub provider URL: {provider_url}")
        repository, ref, mrs_path = match.groups()
    else:
        raise BuildError(f"Unsupported provider URL host: {provider_url}")

    if repository == BETT_REPO and ref == "meta":
        commit = bett_commit
    elif repository == CONVERTER_REPO and ref == "main":
        commit = converter_commit
        if mrs_path != CONVERTER_GEOLOCATION_LIST_PATH.removesuffix(".list"):
            raise BuildError(
                f"Unsupported proxy-rules-converter provider path: {mrs_path}.mrs"
            )
    else:
        raise BuildError(
            f"Unsupported provider source {repository}@{ref}: {provider_url}"
        )

    text_path = mrs_path + ".list"
    return {
        "provider_url": provider_url,
        "repository": repository,
        "ref": ref,
        "commit": commit,
        "path": text_path,
        "url": (
            f"https://raw.githubusercontent.com/{repository}/{commit}/{text_path}"
        ),
    }


def download_text(url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "egern-config-builder/1"})
    with urllib.request.urlopen(request, timeout=60) as response:
        if getattr(response, "status", 200) != 200:
            raise BuildError(f"HTTP error while fetching {url}")
        return response.read().decode("utf-8-sig")


def source_rule_count(text: str) -> int:
    return sum(
        1
        for raw in text.splitlines()
        if (line := raw.strip()) and not line.startswith(("#", ";", "//"))
    )


def output_rule_count(rule: dict[str, Any]) -> int:
    return sum(len(value) for value in rule.values() if isinstance(value, list))


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
    result = {key: value for key, value in fields.items() if value}
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
        target.append(line)
    result: dict[str, Any] = {"no_resolve": True}
    if ipv4:
        result["ip_cidr_set"] = ipv4
    if ipv6:
        result["ip_cidr6_set"] = ipv6
    if len(result) == 1:
        raise BuildError("IP source produced an empty rule set")
    return result


def parse_classical_rule_list(text: str) -> dict[str, Any]:
    fields: dict[str, list[str]] = {
        "domain_set": [],
        "domain_keyword_set": [],
        "domain_suffix_set": [],
        "ip_cidr_set": [],
        "ip_cidr6_set": [],
    }
    no_resolve = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";", "//")):
            continue
        parts = [part.strip() for part in line.split(",")]
        kind = parts[0]
        if len(parts) < 2 or not parts[1]:
            raise BuildError(f"Invalid classical rule: {line!r}")
        value = parts[1]
        if kind == "DOMAIN":
            fields["domain_set"].append(value)
        elif kind == "DOMAIN-KEYWORD":
            fields["domain_keyword_set"].append(value)
        elif kind == "DOMAIN-SUFFIX":
            fields["domain_suffix_set"].append(value)
        elif kind in {"IP-CIDR", "IP-CIDR6"}:
            try:
                network = ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise BuildError(f"Invalid classical IP network {value!r}") from exc
            expected_version = 4 if kind == "IP-CIDR" else 6
            if network.version != expected_version:
                raise BuildError(f"{kind} has the wrong address family: {value!r}")
            target = "ip_cidr_set" if network.version == 4 else "ip_cidr6_set"
            fields[target].append(value)
            no_resolve = no_resolve or "no-resolve" in parts[2:]
        else:
            raise BuildError(f"Unsupported classical rule: {line!r}")
    result: dict[str, Any] = {
        key: values for key, values in fields.items() if values
    }
    if no_resolve:
        result["no_resolve"] = True
    if not result or result == {"no_resolve": True}:
        raise BuildError("Classical source produced an empty rule set")
    return result


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
        {
            "rule_set": {
                "match": f"{RAW_BASE}/rules/{APNS_FILENAME}",
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
        f"{RAW_BASE}/rules/{APNS_FILENAME}",
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
            f"{RAW_BASE}/rules/{filename}",
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
                f"{RAW_BASE}/rules/{filename}",
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
    first_rule = profile["rules"][0].get("rule_set", {})
    if (
        first_rule.get("match") != f"{RAW_BASE}/rules/{APNS_FILENAME}"
        or first_rule.get("policy") != "Proxy"
        or first_rule.get("no_resolve") is not True
    ):
        raise BuildError("APNs rule set must be the first routing rule and use Proxy")
    expected_nameserver_routes = render_nameserver_route_rules(model)
    if profile["rules"][1:1 + len(expected_nameserver_routes)] != expected_nameserver_routes:
        raise BuildError("Mihomo DNS nameserver policy suffixes were not preserved")
    first_dns_rule = profile["dns"]["forward"][0].get("proxy_rule_set", {})
    if (
        first_dns_rule.get("match") != f"{RAW_BASE}/rules/{APNS_FILENAME}"
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
        raise BuildError("Egern subscriptions must default to the 订阅 group")
    if profile.get("default_proxy_group") != "Proxy":
        raise BuildError("Egern proxies must default to the Proxy group")
    if "auto_update" in profile:
        raise BuildError("Egern profile updates must remain manual to preserve local subscriptions")
    for target in ("Telegram", "媒体"):
        if target not in names:
            raise BuildError(f"Required policy group is missing: {target}")
        if "订阅" not in groups[names.index(target)].get("policies", []):
            raise BuildError(f"{target} must include the 订阅 policy group")
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
    if profile.get("hijack_dns") != ["*"]:
        raise BuildError("Egern DNS hijacking must cover all DNS traffic")
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
    for hostname, target in FLOWER_HOSTS.items():
        if dns["hosts"].get(hostname) != target:
            raise BuildError(f"Flower host mapping missing: {hostname}")


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
    parser.add_argument("--converter-commit", required=True)
    parser.add_argument("--apns-commit", required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    try:
        model = json.loads(args.model.read_text(encoding="utf-8"))
        providers = model["providers"]
        wanted = referenced_providers(model)
        generated: dict[str, dict[str, Any]] = {}
        provider_files: dict[str, str] = {}
        source_records: list[dict[str, Any]] = []

        converter_report_url = (
            f"https://raw.githubusercontent.com/{CONVERTER_REPO}/"
            f"{args.converter_commit}/{CONVERTER_GEOLOCATION_REPORT_PATH}"
        )
        converter_report_text = download_text(converter_report_url)
        converter_report = json.loads(converter_report_text)
        converter_expected_entries = converter_report.get("mrs_compatible_entries")
        converter_expected_sha256 = (
            converter_report.get("sha256", {}).get("domain_list")
        )
        if (
            not isinstance(converter_expected_entries, int)
            or converter_expected_entries <= 0
            or not isinstance(converter_expected_sha256, str)
            or not re.fullmatch(r"[0-9a-f]{64}", converter_expected_sha256)
        ):
            raise BuildError("Invalid proxy-rules-converter geolocation-cn report")

        apns_url = (
            f"https://raw.githubusercontent.com/{APNS_REPO}/"
            f"{args.apns_commit}/{APNS_PATH}"
        )
        apns_source = download_text(apns_url)
        apns_rule = parse_classical_rule_list(apns_source)
        apns_source_entries = source_rule_count(apns_source)
        apns_output_entries = output_rule_count(apns_rule)
        if apns_output_entries != apns_source_entries:
            raise BuildError(
                "APNs conversion changed the rule count: "
                f"{apns_source_entries} -> {apns_output_entries}"
            )
        generated[APNS_FILENAME] = apns_rule
        source_records.append({
            "provider": "apns",
            "behavior": "classical",
            "source_repository": APNS_REPO,
            "source_ref": "main",
            "source_commit": args.apns_commit,
            "source_path": APNS_PATH,
            "source_url": apns_url,
            "output": f"rules/{APNS_FILENAME}",
            "source_entries": apns_source_entries,
            "entries": apns_output_entries,
            "source_sha256": hashlib.sha256(
                apns_source.encode("utf-8")
            ).hexdigest(),
        })

        for name in wanted:
            provider = providers.get(name)
            if provider is None:
                raise BuildError(f"Mihomo model is missing provider {name}")
            source_info = resolve_provider_source(
                provider,
                bett_commit=args.bett_commit,
                converter_commit=args.converter_commit,
            )
            source = download_text(source_info["url"])
            behavior = provider.get("behavior")
            if behavior == "domain":
                rule = parse_domain_list(source)
            elif behavior == "ipcidr":
                rule = parse_ip_list(source)
            else:
                raise BuildError(f"Unsupported provider behavior {behavior!r} for {name}")

            source_entries = source_rule_count(source)
            entries = output_rule_count(rule)
            if entries != source_entries:
                raise BuildError(
                    f"{name} conversion changed the rule count: "
                    f"{source_entries} -> {entries}"
                )
            source_sha256 = hashlib.sha256(source.encode("utf-8")).hexdigest()
            record: dict[str, Any] = {
                "provider": name,
                "behavior": behavior,
                "provider_url": source_info["provider_url"],
                "source_repository": source_info["repository"],
                "source_ref": source_info["ref"],
                "source_commit": source_info["commit"],
                "source_path": source_info["path"],
                "source_url": source_info["url"],
                "output": f"rules/{slug(name)}.yaml",
                "source_entries": source_entries,
                "entries": entries,
                "source_sha256": source_sha256,
            }
            if name == "geolocation-cn":
                if source_info["repository"] != CONVERTER_REPO:
                    raise BuildError(
                        "geolocation-cn did not resolve from proxy-rules-converter"
                    )
                if source_info["path"] != CONVERTER_GEOLOCATION_LIST_PATH:
                    raise BuildError(
                        "geolocation-cn resolved to an unexpected converter path"
                    )
                if entries != converter_expected_entries:
                    raise BuildError(
                        "geolocation-cn entry count disagrees with converter report: "
                        f"{entries} != {converter_expected_entries}"
                    )
                if source_sha256 != converter_expected_sha256:
                    raise BuildError(
                        "geolocation-cn SHA-256 disagrees with converter report"
                    )
                record["expected_entries"] = converter_expected_entries

            filename = slug(name) + ".yaml"
            provider_files[name] = filename
            generated[filename] = rule
            source_records.append(record)

        groups, filters = render_policy_groups(model)
        rules = render_rules(model, provider_files)
        profile = {
            "ipv6": True,
            "hijack_dns": ["*"],
            "block_quic": False,
            "include_all_networks": True,
            "include_apns": True,
            "default_subscription_group": "订阅",
            "default_proxy_group": "Proxy",
            "dns": {
                "bootstrap": bootstrap_nameservers(model),
                "upstreams": {"Foreign": nameservers(model)},
                "forward": render_dns_forward(model, providers, provider_files),
                "hosts": hosts(model),
                "proxy_nameservers": MESL_PROXY_DNS,
            },
            "policy_groups": groups,
            "rules": rules,
        }
        validate_profile(profile, generated, model, provider_files)

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
            "schema_version": 2,
            "mihomo_script": {
                "repository": MIHOMO_REPO,
                "commit": args.mihomo_commit,
            },
            "bett_rules": {
                "repository": BETT_REPO,
                "branch": "meta",
                "commit": args.bett_commit,
            },
            "proxy_rules_converter": {
                "repository": CONVERTER_REPO,
                "branch": "main",
                "commit": args.converter_commit,
                "geolocation_cn": {
                    "list_path": CONVERTER_GEOLOCATION_LIST_PATH,
                    "report_path": CONVERTER_GEOLOCATION_REPORT_PATH,
                    "report_url": converter_report_url,
                    "report_sha256": hashlib.sha256(
                        converter_report_text.encode("utf-8")
                    ).hexdigest(),
                    "expected_entries": converter_expected_entries,
                },
            },
            "apns_rules": {
                "repository": APNS_REPO,
                "branch": "main",
                "path": APNS_PATH,
                "commit": args.apns_commit,
            },
            "profile_sha256": hashlib.sha256(profile_text.encode("utf-8")).hexdigest(),
            "policy_groups": len(groups),
            "routing_rules": len(rules),
            "native_rule_sets": source_records,
            "group_filters": filters,
            "dns": {
                "bootstrap": profile["dns"]["bootstrap"],
                "forward_rules": len(profile["dns"]["forward"]),
                "nameserver_route_rules": len(render_nameserver_route_rules(model)),
                "proxy_nameservers": profile["dns"]["proxy_nameservers"],
            },
            "subscription": {
                "group": "订阅",
                "default_proxy_group": "Proxy",
                "urls_published": False,
                "reason": "Subscription credentials must not be committed to a public repository.",
            },
            "migration_boundaries": [
                "Mihomo IPv4/IPv6 preferred DIRECT pseudo-proxies map to Egern DIRECT.",
                "Mihomo default-nameserver endpoints map to plain-UDP bootstrap IPs because Egern bootstrap only supports plain UDP.",
                "Mihomo nameserver policy suffixes map to explicit Egern routing rules for the DNS server endpoints.",
                "Mihomo nameserver-policy and explicit Direct domain rules map to Egern Forward system rules; Egern cannot re-resolve from a runtime policy-group selection.",
                "Mihomo fakeip_filter is intentionally left to Egern native Fake-IP handling.",
                "The user-requested APNs list is converted from classical syntax to one Egern-native mixed rule set and placed first with Proxy/Foreign DNS handling.",
                "Mihomo fakeip_filter and the user-requested APNs override are the only approved rule-set migration exceptions.",
                "Every other provider text source is resolved from the Mihomo provider's final URL and pinned to an immutable commit; MRS is not decoded.",
                "Rule-set conversion preserves every source rule, duplicate, spelling, and per-field order; only Egern-native syntax mapping is performed.",
            ],
        }
        report_text = json.dumps(report_data, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        if write_or_check(REPORT_PATH, report_text, args.check):
            changed.append("reports/source.json")

        if args.check and changed:
            raise BuildError("Generated files are out of date: " + ", ".join(changed))
        print(
            f"Generated {len(groups)} policy groups, {len(rules)} routing rules, "
            f"{len(generated)} native Egern rule sets."
        )
        return 0
    except (BuildError, OSError, ValueError, KeyError, json.JSONDecodeError, yaml.YAMLError) as exc:
        print(f"Build failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
