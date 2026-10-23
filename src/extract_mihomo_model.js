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
  ";const __egernRegionMap = new Map([...regionDefinitions, ...rateRegionDefinitions, {name: '其他节点'}]",
  "  .map(({name}) => [name, ['__' + name + '__']]));",
  ";globalThis.__egernModel = {",
  "  providers: finalRuleProviders,",
  "  rules: finalRules,",
  "  groups: buildProxyGroups(__egernRegionMap, [{name: '__SUBSCRIPTION__'}]),",
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
