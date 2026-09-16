#!/usr/bin/env node
"use strict";

const fs = require("fs");
const vm = require("vm");

if (process.argv.length !== 3) {
  throw new Error("usage: node extract_mihomo_model.js <mihomoScript.js>");
}

const source = fs.readFileSync(process.argv[2], "utf8");
const exportCode = [
  "",
  ";const __egernDnsAndHosts = buildDnsAndHostsConfig({dns: {}, hosts: {}}, []);",
  ";globalThis.__egernModel = {",
  "  providers: buildRuleProviders(),",
  "  rules: buildRules(),",
  "  groups: buildProxyGroups(new Map([",
  "    ['台湾省', [{name: '__台湾__'}]],",
  "    ['新加坡', [{name: '__新加坡__'}]],",
  "    ['日本', [{name: '__日本__'}]],",
  "    ['美国', [{name: '__美国__'}]],",
  "    ['其他节点', [{name: '__其他节点__'}]],",
  "    ['低倍率节点', [{name: '__低倍率节点__'}]],",
  "  ]), [{name: '__SUBSCRIPTION__'}]),",
  "  regions: regionDefinitions.map(({name, regex}) => ({name, source: regex.source, flags: regex.flags})),",
  "  rateRegions: rateRegionDefinitions.map(({name, regex}) => ({name, source: regex.source, flags: regex.flags})),",
  "  excludeFilter: {source: excludeFilter.source, flags: excludeFilter.flags},",
  "  options: ruleOptionsEnable,",
  "  dns: __egernDnsAndHosts.dns,",
  "  hosts: __egernDnsAndHosts.hosts,",
  "};",
].join("\n");

const sandbox = {};
vm.createContext(sandbox);
vm.runInContext(source + exportCode, sandbox, {timeout: 5000});
process.stdout.write(JSON.stringify(sandbox.__egernModel, null, 2) + "\n");
