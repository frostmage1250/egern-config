#!/usr/bin/env node
"use strict";

const fs = require("fs");
const vm = require("vm");

if (process.argv.length !== 3) throw new Error("usage: node extract_mihomo_model.js <mihomoScript.js>");
const source = fs.readFileSync(process.argv[2], "utf8");
const exportCode = `
;const __egernDefinitions = typeof allRegionDefinitions !== "undefined"
  ? allRegionDefinitions
  : [...regionDefinitions, ...rateRegionDefinitions,
      ...(typeof homeRegionDefinitions === "undefined" ? [] : homeRegionDefinitions)];
;const __egernNames = ["__SUBSCRIPTION__"];
;for (const definition of __egernDefinitions) {
  const candidates = [definition.flag, definition.name, definition.name + " 0.5x",
    definition.name + " 3x", definition.name + " 100x"].filter(Boolean);
  const name = candidates.map(value => "__" + value + "__").find(value => {
    definition.regex.lastIndex = 0;
    return definition.regex.test(value);
  });
  if (!name) throw new Error("Cannot represent upstream node group: " + definition.name);
  if (!__egernNames.includes(name)) __egernNames.push(name);
}
;const __egernConfig = main({
  proxies: __egernNames.map(name => ({name, type:"ss", server:"192.0.2.1", port:443,
    cipher:"aes-128-gcm", password:"model-extraction-placeholder"})),
  dns:{}, hosts:{}
});
;const __egernGroupNames = new Set(__egernConfig["proxy-groups"].map(group => group.name));
;globalThis.__egernModel = {
  providers: __egernConfig["rule-providers"],
  rules: __egernConfig.rules,
  quic_rules: typeof blockForeignQuic === "undefined" ? [] : blockForeignQuic,
  groups: __egernConfig["proxy-groups"],
  regions: regionDefinitions.filter(entry => __egernGroupNames.has(entry.name))
    .map(({name,regex}) => ({name,source:regex.source,flags:regex.flags})),
  rateRegions: rateRegionDefinitions.filter(entry => __egernGroupNames.has(entry.name))
    .map(({name,regex}) => ({name,source:regex.source,flags:regex.flags})),
  homeRegions: (typeof homeRegionDefinitions === "undefined" ? [] : homeRegionDefinitions)
    .filter(entry => __egernGroupNames.has(entry.name))
    .map(({name,regex}) => ({name,source:regex.source,flags:regex.flags})),
  lowRateRegionName: typeof lowRateRegionName === "undefined" ? "低倍率节点" : lowRateRegionName,
  highRateRegionName: typeof highRateRegionName === "undefined" ? "高倍率节点" : highRateRegionName,
  excludeFilter: {source:excludeFilter.source,flags:excludeFilter.flags},
  options: ruleOptionsEnable,
  dns: __egernConfig.dns,
  hosts: __egernConfig.hosts
};
`;
const sandbox = {};
vm.createContext(sandbox);
vm.runInContext(source + exportCode, sandbox, {timeout: 5000});
process.stdout.write(JSON.stringify(sandbox.__egernModel, null, 2) + "\n");
