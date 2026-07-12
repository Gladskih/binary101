"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { PeBunPackerFinding } from "../../../../analyzers/pe/packers/types.js";
import { renderBunFindingDetails } from "../../../../renderers/pe/bun-packer.js";

const createFinding = (): PeBunPackerFinding => ({
  id: "bun-standalone",
  name: "Bun standalone executable",
  kind: "runtime-packager",
  confidence: "high",
  evidence: ["Bun verified"],
  sectionStart: 0x400,
  sectionSize: 0x200,
  payloadStart: 0x408,
  payloadSize: 0x180,
  storage: "u64-length-prefixed",
  offsetMetadata: {
    byteCount: 0x100,
    compileArgvBytes: 12,
    entryPointId: 3,
    flags: 0x03,
    moduleListBytes: 64
  }
});

void test("renderBunFindingDetails splits raw and payload ranges into comparable rows", () => {
  const html = renderBunFindingDetails(createFinding());

  assert.ok(html.includes(
    `<tr><th scope="row" class="peBunTable__field">.bun raw start</th>` +
    `<td class="peNumeric">0x00000400</td>` +
    `<td class="smallNote pePackerFinding__meaning">` +
    `First raw file byte occupied by the .bun section.</td></tr>`
  ));
  assert.match(html, /\.bun raw end[\s\S]*0x00000600/);
  assert.ok(html.includes(
    `.bun raw size</th><td class="peNumeric">512 bytes</td>`
  ));
  assert.match(html, /Payload start[\s\S]*0x00000408/);
  assert.match(html, /Payload end[\s\S]*0x00000588/);
  assert.match(html, /Payload size[\s\S]*384 bytes/);
  assert.ok(html.includes("Exclusive end of the .bun section's raw file data."));
  assert.ok(html.includes("Raw file size declared by the PE section table."));
  assert.ok(html.includes("First byte of the validated standalone module graph."));
  assert.ok(html.includes("Exclusive end of the validated standalone module graph."));
  assert.ok(html.includes("Validated standalone module-graph payload size."));
  assert.doesNotMatch(html, /0x00000400-0x00000600/);
});

void test("renderBunFindingDetails changes byte formatting at one kibibyte", () => {
  const html = renderBunFindingDetails({
    ...createFinding(),
    sectionSize: 1024,
    payloadSize: 1023
  });

  assert.match(html, /\.bun raw size[\s\S]*1 KB \(1024 bytes\)/);
  assert.match(html, /Payload size[\s\S]*1023 bytes/);
});

void test("renderBunFindingDetails renders every storage choice and selects the active one", () => {
  const html = renderBunFindingDetails(createFinding());

  assert.ok(html.startsWith(
    `<div class="tableWrap"><table class="table peBunTable pePackerFinding__details">` +
    `<thead><tr><th>Field</th><th>Value</th><th>Meaning</th></tr></thead><tbody>`
  ));
  assert.ok(html.includes(
    `<th scope="row" class="peBunTable__field">Storage</th><td><div class="optionsRow">`
  ));
  assert.match(html, /opt dim[^>]*>32-bit length-prefixed PE section<\/span>/);
  assert.match(html, /opt sel[^>]*>64-bit length-prefixed PE section<\/span>/);
  assert.match(html, /opt dim[^>]*>PE section virtual data<\/span>/);
  assert.ok(html.includes(
    "32-bit length-prefixed PE section - A 4-byte little-endian payload length precedes the graph"
  ));
  assert.ok(html.includes(
    "64-bit length-prefixed PE section - An 8-byte little-endian payload length precedes the graph"
  ));
  assert.ok(html.includes(
    "PE section virtual data - The payload occupies the meaningful virtual extent of the section"
  ));
  assert.ok(html.includes("How the embedded Bun payload is stored in the PE section."));
});

void test("renderBunFindingDetails selects virtual-data storage", () => {
  const html = renderBunFindingDetails({
    ...createFinding(),
    storage: "section-virtual-data"
  });

  assert.match(html, /opt dim[^>]*>32-bit length-prefixed PE section<\/span>/);
  assert.match(html, /opt dim[^>]*>64-bit length-prefixed PE section<\/span>/);
  assert.match(html, /opt sel[^>]*>PE section virtual data<\/span>/);
});

void test("renderBunFindingDetails selects 32-bit length-prefixed storage", () => {
  const html = renderBunFindingDetails({
    ...createFinding(),
    storage: "u32-length-prefixed"
  });

  assert.match(html, /opt sel[^>]*>32-bit length-prefixed PE section<\/span>/);
  assert.match(html, /opt dim[^>]*>64-bit length-prefixed PE section<\/span>/);
  assert.match(html, /opt dim[^>]*>PE section virtual data<\/span>/);
});

void test("renderBunFindingDetails renders known flags as active and inactive chips", () => {
  const html = renderBunFindingDetails(createFinding());

  assert.match(html, /opt sel[^>]*>Disable env files<\/span>/);
  assert.match(html, /opt sel[^>]*>Disable bunfig<\/span>/);
  assert.match(html, /opt dim[^>]*>Disable tsconfig<\/span>/);
  assert.match(html, /opt dim[^>]*>Disable package.json<\/span>/);
  assert.ok(html.includes("Disable env files - Do not load the default environment files"));
  assert.ok(html.includes("Disable bunfig - Do not automatically load bunfig.toml"));
  assert.ok(html.includes("Disable tsconfig - Do not automatically load tsconfig.json"));
  assert.ok(html.includes("Disable package.json - Do not automatically load package.json"));
  assert.doesNotMatch(html, /UNKNOWN_BITS/);
});

void test("renderBunFindingDetails explains every parsed offset field", () => {
  const html = renderBunFindingDetails(createFinding());

  assert.equal(html.match(/<td class="peNumeric">/g)?.length, 10);
  assert.match(html, /Graph byte count[\s\S]*256 bytes/);
  assert.ok(html.includes("Payload bytes declared by Bun's embedded module graph."));
  assert.match(html, /Entry point id[\s\S]*>3<\/td>/);
  assert.ok(html.includes(
    "Identifier of the embedded module selected as the program entry point."
  ));
  assert.match(html, /Module-list bytes[\s\S]*64 bytes/);
  assert.ok(html.includes("Encoded byte length of the embedded module list."));
  assert.match(html, /Compile argv bytes[\s\S]*12 bytes/);
  assert.ok(html.includes("Encoded byte length of arguments captured by Bun's compiler."));
  assert.ok(html.includes(
    `<th scope="row" class="peBunTable__field">Flags</th><td><div class="optionsRow">`
  ));
  assert.ok(html.includes("Standalone compile options stored in Bun's Flags bitmask."));
});

void test("renderBunFindingDetails exposes unknown reserved flag bits", () => {
  const finding = createFinding();
  finding.offsetMetadata = { ...finding.offsetMetadata!, flags: 0x13 };

  const html = renderBunFindingDetails(finding);

  assert.match(html, /UNKNOWN_BITS_0x0010/);
});

void test("renderBunFindingDetails omits unavailable offset metadata", () => {
  const finding = createFinding();
  delete finding.offsetMetadata;

  const html = renderBunFindingDetails(finding);

  assert.ok(html.includes("Storage"));
  assert.doesNotMatch(html, /Graph byte count|Entry point id|>Flags</);
  assert.ok(html.endsWith(`</td></tr></tbody></table></div>`));
});
