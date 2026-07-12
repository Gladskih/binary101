"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { PeNsisPackerFinding } from "../../../../analyzers/pe/packers/types.js";
import { renderNsisFindingDetails } from "../../../../renderers/pe/nsis-installer.js";

const createFinding = (): PeNsisPackerFinding => ({
  id: "nsis-installer",
  name: "NSIS installer",
  kind: "installer",
  confidence: "high",
  evidence: ["NSIS verified"],
  headerSize: 512,
  firstHeaderOffset: 0x400,
  flags: 0x05,
  followingDataSize: 0x800
});

void test("renderNsisFindingDetails renders validated bounds", () => {
  const html = renderNsisFindingDetails(createFinding());

  assert.ok(html.startsWith(
    `<div class="tableWrap"><table class="table peNsisTable pePackerFinding__details">` +
    `<thead><tr><th>Field</th><th>Value</th><th>Meaning</th></tr></thead><tbody>`
  ));
  assert.match(html, /Installer data start[\s\S]*0x00000400/);
  assert.ok(html.includes("File offset of the validated NSIS firstheader and installer data."));
  assert.match(html, /Installer data end[\s\S]*0x00000c00/);
  assert.ok(html.includes(
    "Exclusive end derived from firstheader length_of_all_following_data."
  ));
  assert.match(html, /Installer data size[\s\S]*2 KB \(2048 bytes\)/);
  assert.ok(html.includes(
    "Validated length_of_all_following_data value from firstheader."
  ));
  assert.ok(html.includes(
    `Unpacked header size</th><td class="peNumeric">512 bytes</td>`
  ));
  assert.ok(html.includes("Size allocated for decompressed NSIS headers (length_of_header)."));
  assert.ok(html.includes("Validated firstheader flags; active options are highlighted."));
  assert.ok(html.includes(
    `<th scope="row" class="peNsisTable__field">Flags</th><td><div class="optionsRow">`
  ));
  assert.ok(html.endsWith(`</tbody></table></div>`));
  assert.doesNotMatch(html, /data-pe-overlay-download|data-pe-overlay-scan/);
});

void test("renderNsisFindingDetails renders a validated archive download", () => {
  const html = renderNsisFindingDetails(createFinding(), [{
    start: 0x500,
    end: 0xb00,
    format: "sevenzip",
    provenance: {
      location: "overlay",
      discovery: "archive-scan",
      association: "nsis-installer-data",
      validation: "sevenzip-next-header"
    }
  }]);

  assert.ok(html.includes("Archive in NSIS installer data"));
  assert.ok(html.includes("7z archive"));
  assert.ok(html.includes(`data-pe-payload-download`));
  assert.ok(html.includes(`data-payload-start="1280"`));
  assert.ok(html.includes(`data-payload-end="2816"`));
  assert.doesNotMatch(html, /data-pe-overlay-download|data-pe-overlay-scan/);
});

void test("renderNsisFindingDetails changes byte formatting at one kibibyte", () => {
  const html = renderNsisFindingDetails({
    ...createFinding(),
    headerSize: 1023,
    followingDataSize: 1024
  });

  assert.ok(html.includes(
    `Installer data size</th><td class="peNumeric">1 KB (1024 bytes)</td>`
  ));
  assert.ok(html.includes(
    `Unpacked header size</th><td class="peNumeric">1023 bytes</td>`
  ));
});

void test("renderNsisFindingDetails shows every flag and highlights active options", () => {
  const html = renderNsisFindingDetails(createFinding());

  assert.match(html, /opt sel[^>]*>Uninstaller<\/span>/);
  assert.match(html, /opt dim[^>]*>Silent<\/span>/);
  assert.match(html, /opt sel[^>]*>No CRC<\/span>/);
  assert.match(html, /opt dim[^>]*>Force CRC<\/span>/);
  assert.ok(html.includes("Uninstaller - The data belongs to an NSIS uninstaller"));
  assert.ok(html.includes("Silent - Run with silent mode enabled"));
  assert.ok(html.includes("No CRC - Do not perform the normal CRC check"));
  assert.ok(html.includes("Force CRC - Force the CRC check"));
  assert.doesNotMatch(html, /UNKNOWN_BITS/);
});

void test("renderNsisFindingDetails keeps unexpected flag bits visible", () => {
  const html = renderNsisFindingDetails({ ...createFinding(), flags: 0x10 });

  assert.match(html, /UNKNOWN_BITS_0x0010/);
});
