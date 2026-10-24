import assert from "node:assert/strict";
import { test } from "node:test";
import { buildLegacyCodeViewProcedureTables } from "../../../../renderers/pe/legacy-codeview-procedure-tables.js";
import { createLegacyCodeViewInfo } from "../../../fixtures/pe-legacy-codeview-view.js";

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
