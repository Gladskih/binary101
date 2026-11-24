import assert from "node:assert/strict";
import { test } from "node:test";
import { renderHeaders } from "../../../../../renderers/pe/headers.js";
import { getPeLazySectionDescriptors } from "../../../../../renderers/pe/lazy-section-shells.js";
import { createBasePe } from "../../../../fixtures/pe-renderer-headers-fixture.js";

void test("unreadable directories keep their warnings in the data directory table panel", () => {
  const pe = createBasePe();
  pe.dirs = [
    { name: "EXPORT", rva: 0x4000, size: 40 },
    { name: "IMPORT", rva: 0x4000, size: 20 },
    { name: "RESOURCE", rva: 0, size: 16 }
  ];
  pe.imports.warning = "Import directory RVA does not map to file data.";
  pe.exports = {
    headerRead: false, flags: 0, timestamp: 0, version: 0, dllName: "", Base: 0,
    NumberOfFunctions: 0, NumberOfNames: 0, namePointerTable: 0, ordinalTable: 0,
    entries: [], issues: ["Export directory RVA does not map to file data."]
  };
  pe.resources = {
    top: [], detail: [], issues: ["Resource directory has a non-zero size but RVA is 0."]
  };
  const descriptors = getPeLazySectionDescriptors(pe).map(section => section.key);
  const out: string[] = [];
  renderHeaders(pe, out);

  assert.ok(!descriptors.includes("imports"));
  assert.ok(!descriptors.includes("exports"));
  assert.ok(!descriptors.includes("resources"));
  const html = out.join("");
  assert.equal([...html.matchAll(/peDataDirectoryStatus--unverified/g)].length, 3);
  assert.match(html, /Import warnings/);
  assert.match(html, /Export warnings/);
  assert.match(html, /Resource warnings/);
});
