import assert from "node:assert/strict";
import { test } from "node:test";
import { buildLegacyCodeViewProcedureTables } from "../../../../renderers/pe/legacy-codeview-procedure-tables.js";
import { createLegacyCodeViewInfo } from "../../../fixtures/pe-legacy-codeview-view.js";
import { createBasePe } from "../../../fixtures/pe-renderer-headers-fixture.js";
import { codeViewAddressInfo, codeViewAddressSections } from "../../../fixtures/pe-codeview-procedure-addresses.js";

void test("CodeView procedure rows preserve names, stored spans, references, flags, and raw scope offsets", () => {
  const info = createLegacyCodeViewInfo();
  const section = info.directories[0]!.subsections.find(value => value.data?.kind === "symbols")!;
  section.data = { kind: "symbols", records: [
    { type: 0x1147, name: "GlobalFunction", procedure: { referenceKind: "procedureId", reference: 4097,
      codeLength: 160, debugStart: 16, debugEnd: 144, storedLocation: { segment: 9, offset: 4660 },
      scopeOffsets: { parent: 16, end: 32, next: 48 }, flags: 0xd5 } },
    { type: 0x110f, procedure: { referenceKind: "typeIndex" } },
    { type: 0x1110, name: "LocalFlags", procedure: { referenceKind: "typeIndex", reference: 4098,
      codeLength: 32, debugStart: 0, debugEnd: 32, storedLocation: { segment: 4, offset: 0 },
      scopeOffsets: { parent: 0, end: 0, next: 0 }, flags: 0x2a } },
    { type: 0x110f, name: "NoFlags", procedure: { referenceKind: "typeIndex", reference: 4099,
      flags: 0 } }
  ] };

  assert.deepEqual(buildLegacyCodeViewProcedureTables(info), [{ key: "procedureSymbols",
    title: "Procedure symbols",
    columns: ["Directory", "Module", "Container", "Procedure kind", "Name", "Type or ID link",
      "Stored segment:offset", "Code length", "Debug span", "Raw parent/end/next offsets", "Flags"],
    rows: [["1", "1", "(top level)", "Global procedure", "GlobalFunction", "Procedure ID 4097",
      "9:4660", "160", "16 to 144", "parent 16; end 32; next 48",
      "Frame pointer present, Far return, Not reached, No inline, Optimized debug information"],
      ["1", "1", "(top level)", "Local procedure", "(name unavailable)", "unavailable",
        "unavailable", "unavailable", "unavailable", "unavailable", "unavailable"],
      ["1", "1", "(top level)", "Global procedure", "LocalFlags", "Type index 4098",
        "4:0", "32", "0 to 32", "parent 0; end 0; next 0",
        "Interrupt return, Never returns, Custom calling convention"],
      ["1", "1", "(top level)", "Local procedure", "NoFlags", "Type index 4099",
        "unavailable", "unavailable", "unavailable", "unavailable", "None"]] }]);
});

void test("CodeView procedure table omits directories without procedure symbols", () => {
  assert.deepEqual(buildLegacyCodeViewProcedureTables(createLegacyCodeViewInfo()), []);
});

void test("CodeView procedure image addresses retain names and summarize unresolved ranges", () => {
  const info = codeViewAddressInfo();
  const pe = createBasePe();
  pe.sections = codeViewAddressSections();
  info.directories[0]!.subsections.push({ type: 0x125, module: 1, offset: 32, size: 128,
    data: { kind: "symbols", records: [
      { type: 0x1110, name: "<mapped>&amp;", procedure: { referenceKind: "typeIndex", codeLength: 32,
        storedLocation: { segment: 1, offset: 16 } } },
      { type: 0x110f, name: "too_long", procedure: { referenceKind: "typeIndex", codeLength: 64,
        storedLocation: { segment: 1, offset: 16 } } },
      { type: 0x110f, name: "<second>", procedure: { referenceKind: "typeIndex", codeLength: 32,
        storedLocation: { segment: 1, offset: 16 } } }
    ] } });
  const tables = buildLegacyCodeViewProcedureTables(info, pe);

  assert.deepEqual(tables[0], { key: "procedureAddresses", title: "Procedure address resolution",
    columns: ["Result", "Records"], rows: [["Resolved in #2 .code", "2"],
      ["Unresolved: Procedure exceeds logical segment bounds.", "1"]] });
  assert.deepEqual(tables[1]?.columns.slice(0, 5), ["Name", "Image RVA", "PE section", "Code length", "Address resolution"]);
  assert.deepEqual(tables[1]?.rows[0]?.slice(0, 5), ["<mapped>&amp;", "0x3030", "#2 .code", "32",
    "Full stored range fits the image section"]);
  assert.deepEqual(tables[1]?.rows[1]?.slice(0, 5), ["too_long", "unresolved", "unavailable", "64",
    "Procedure exceeds logical segment bounds."]);
  assert.deepEqual(buildLegacyCodeViewProcedureTables(createLegacyCodeViewInfo(), pe), []);
});

void test("Discarded procedures never acquire an RVA even through nested symbol containers", () => {
  const info = codeViewAddressInfo();
  const pe = createBasePe();
  pe.sections = codeViewAddressSections();
  info.directories[0]!.subsections.push({ type: 0x125, module: 1, offset: 32, size: 128,
    data: { kind: "symbols", records: [{ type: 0x113b, children: [{ type: 0xe, children: [
      { type: 0x1110, name: "removed_function", procedure: { referenceKind: "typeIndex", codeLength: 32,
        storedLocation: { segment: 1, offset: 16 } } }
    ] }] }] } });
  const tables = buildLegacyCodeViewProcedureTables(info, pe);

  assert.deepEqual(tables[1]?.rows[0]?.slice(0, 5), ["removed_function", "unresolved", "unavailable", "32",
    "Discarded symbol does not identify current image code."]);
});

void test("Type-embedded procedures keep their names without assuming an image address context", () => {
  const info = codeViewAddressInfo();
  const pe = createBasePe();
  pe.sections = codeViewAddressSections();
  info.directories[0]!.subsections.push({ type: 0x121, module: 1, offset: 32, size: 128,
    data: { kind: "types", records: [{ type: 0x20c, symbols: [
      { type: 0x1110, name: "type_function", procedure: { referenceKind: "typeIndex", codeLength: 32,
        storedLocation: { segment: 1, offset: 16 } } }
    ] }] } });
  const tables = buildLegacyCodeViewProcedureTables(info, pe);

  assert.deepEqual(tables[1]?.rows[0]?.slice(0, 5), ["type_function", "unresolved", "unavailable", "32",
    "Type-embedded symbol address context is not established."]);
});
