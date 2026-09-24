"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { PeDynamicRelocations } from
  "../../../../../analyzers/pe/dynamic-relocations/index.js";
import { linkDynamicImportControlTransfers } from
  "../../../../../analyzers/pe/dynamic-relocations/import-links.js";
import type { PeImportParseResult } from "../../../../../analyzers/pe/imports/index.js";
import { MockFile } from "../../../../helpers/mock-file.js";

const makeTable = (iatIndex = 1): PeDynamicRelocations => ({ version: 1, dataSize: 12,
  entries: [{ kind: "v1", symbol: 3n, baseRelocSize: 12, availableBytes: 12,
    controlTransfers: [{ kind: "import", rva: 0x1010,
      indirectCall: true, iatIndex }] }] });

const makeCodeFile = (opcode = 0x15, targetRva = 0x2008): MockFile => {
  const bytes = new Uint8Array(0x3000);
  bytes.set([0x48, 0xff, opcode], 0x1010); // x64 CALL/JMP qword ptr [RIP+disp32].
  new DataView(bytes.buffer).setInt32(0x1013, targetRva - 0x1017, true);
  return new MockFile(bytes, "dvrt-import.bin");
};

const imports: PeImportParseResult = { thunkEntrySize: 8, entries: [{
  dll: "example.dll", originalFirstThunkRva: 0,
  timeDateStamp: 0, forwarderChain: 0, firstThunkRva: 0x2008,
  lookupSource: "iat-fallback", thunkTableTerminated: true,
  functions: [{ name: "ExampleFunction" }]
}] };

void test("linkDynamicImportControlTransfers verifies the instruction and IAT slot", async () => {
  const linked = await linkDynamicImportControlTransfers(makeTable(), makeCodeFile(),
    rva => rva, { rva: 0x2000, size: 0x20 }, imports);

  assert.deepEqual(linked.entries[0]?.controlTransfers?.[0], {
    kind: "import", rva: 0x1010, indirectCall: true, iatIndex: 1,
    importName: "example.dll!ExampleFunction"
  });
});

void test("linkDynamicImportControlTransfers leaves mismatched IAT indices unresolved", async () => {
  const source = makeTable(2);

  const linked = await linkDynamicImportControlTransfers(source, makeCodeFile(),
    rva => rva, { rva: 0x2000, size: 0x20 }, imports);

  assert.deepEqual(linked, source);
});

void test("linkDynamicImportControlTransfers tolerates missing IAT information", async () => {
  const source = makeTable();

  const linked = await linkDynamicImportControlTransfers(source, makeCodeFile(),
    rva => rva, null, imports);

  assert.deepEqual(linked, source);
});

void test("linkDynamicImportControlTransfers handles indirect jump imports", async () => {
  const source = makeTable();
  source.entries[0]!.controlTransfers![0] = {
    kind: "import", rva: 0x1010, indirectCall: false, iatIndex: 1
  };

  const linked = await linkDynamicImportControlTransfers(source, makeCodeFile(0x25),
    rva => rva, { rva: 0x2000, size: 0x20 }, imports);

  assert.equal(linked.entries[0]?.controlTransfers?.[0]?.kind, "import");
  assert.deepEqual(linked.entries[0]?.controlTransfers?.[0], {
    kind: "import", rva: 0x1010, indirectCall: false, iatIndex: 1,
    importName: "example.dll!ExampleFunction"
  });
});

void test("linkDynamicImportControlTransfers rejects instruction target mismatches", async () => {
  const source = makeTable();

  const linked = await linkDynamicImportControlTransfers(source, makeCodeFile(0x15, 0x2010),
    rva => rva, { rva: 0x2000, size: 0x20 }, imports);

  assert.deepEqual(linked, source);
});

void test("linkDynamicImportControlTransfers rejects an inconsistent call opcode", async () => {
  const source = makeTable();

  const linked = await linkDynamicImportControlTransfers(source, makeCodeFile(0x25),
    rva => rva, { rva: 0x2000, size: 0x20 }, imports);

  assert.deepEqual(linked, source);
});

void test("linkDynamicImportControlTransfers rejects slots outside the IAT", async () => {
  const source = makeTable();

  const linked = await linkDynamicImportControlTransfers(source, makeCodeFile(),
    rva => rva, { rva: 0x2000, size: 8 }, imports);

  assert.deepEqual(linked, source);
});

void test("linkDynamicImportControlTransfers rejects duplicate import slots", async () => {
  const source = makeTable();
  const duplicateImports: PeImportParseResult = { ...imports,
    entries: [imports.entries[0]!, { ...imports.entries[0]!, dll: "other.dll" }] };

  const linked = await linkDynamicImportControlTransfers(source, makeCodeFile(),
    rva => rva, { rva: 0x2000, size: 0x20 }, duplicateImports);

  assert.deepEqual(linked, source);
});

void test("linkDynamicImportControlTransfers reports instruction read failures", async () => {
  const source = makeTable();
  const reader = makeCodeFile();
  reader.read = async () => { throw new Error("read failed"); };

  const linked = await linkDynamicImportControlTransfers(source, reader,
    rva => rva, { rva: 0x2000, size: 0x20 }, imports);

  assert.match(linked.warnings?.[0] ?? "", /could not read an import control-transfer instruction/);
  assert.deepEqual(linked.entries[0]?.controlTransfers, source.entries[0]?.controlTransfers);
});

void test("linkDynamicImportControlTransfers rejects malformed IAT and import RVAs", async () => {
  const source = makeTable();
  const malformedImports: PeImportParseResult = { ...imports, entries: [{
    ...imports.entries[0]!, firstThunkRva: -1
  }] };

  const malformedIat = await linkDynamicImportControlTransfers(source, makeCodeFile(),
    rva => rva, { rva: -1, size: 0x20 }, imports);
  const malformedEntry = await linkDynamicImportControlTransfers(source, makeCodeFile(),
    rva => rva, { rva: 0x2000, size: 0x20 }, malformedImports);

  assert.deepEqual(malformedIat, source);
  assert.deepEqual(malformedEntry, source);
});

void test("linkDynamicImportControlTransfers preserves other entries and records", async () => {
  const source = makeTable();
  source.entries.unshift({ kind: "v1", symbol: 7n,
    baseRelocSize: 0, availableBytes: 0 });
  source.entries[1]!.controlTransfers!.push({
    kind: "switch", rva: 0x1030, registerNumber: 9
  });

  const linked = await linkDynamicImportControlTransfers(source, makeCodeFile(),
    rva => rva, { rva: 0x2000, size: 0x20 }, imports);

  assert.deepEqual(linked.entries[0], source.entries[0]);
  assert.deepEqual(linked.entries[1]?.controlTransfers?.[1],
    source.entries[1]?.controlTransfers?.[1]);
  assert.equal(linked.entries[1]?.controlTransfers?.[0]?.kind, "import");
});

void test("linkDynamicImportControlTransfers links ordinal imports", async () => {
  const ordinalImports: PeImportParseResult = { ...imports, entries: [{
    ...imports.entries[0]!, functions: [{ ordinal: 42 }]
  }] };

  const linked = await linkDynamicImportControlTransfers(makeTable(), makeCodeFile(),
    rva => rva, { rva: 0x2000, size: 0x20 }, ordinalImports);

  assert.deepEqual(linked.entries[0]?.controlTransfers?.[0], {
    kind: "import", rva: 0x1010, indirectCall: true, iatIndex: 1,
    importName: "example.dll!#42"
  });
});

void test("linkDynamicImportControlTransfers ignores unmapped instruction bytes", async () => {
  const source = makeTable();

  const linked = await linkDynamicImportControlTransfers(source, makeCodeFile(),
    () => null, { rva: 0x2000, size: 0x20 }, imports);

  assert.deepEqual(linked, source);
});

void test("linkDynamicImportControlTransfers skips invalid IATs and thunk sizes", async () => {
  const source = makeTable();
  const reader = makeCodeFile();

  assert.deepEqual(await linkDynamicImportControlTransfers(source, reader,
    rva => rva, { rva: 0x2000, size: 0x20, warnings: ["invalid"] }, imports), source);
  assert.deepEqual(await linkDynamicImportControlTransfers(source, reader,
    rva => rva, { rva: 0x2000, size: 0x20 }, { ...imports, thunkEntrySize: 4 }), source);
  assert.deepEqual(await linkDynamicImportControlTransfers(source, reader,
    rva => rva, { rva: 0x2000, size: 0x20 }, { ...imports, entries: [] }), source);
});

void test("linkDynamicImportControlTransfers indexes later import thunks", async () => {
  const laterImports: PeImportParseResult = { ...imports, entries: [{
    ...imports.entries[0]!, functions: [
      { name: "FirstFunction" }, { name: "SecondFunction" }
    ]
  }] };

  const linked = await linkDynamicImportControlTransfers(makeTable(2),
    makeCodeFile(0x15, 0x2010), rva => rva,
    { rva: 0x2000, size: 0x20 }, laterImports);

  assert.deepEqual(linked.entries[0]?.controlTransfers?.[0], {
    kind: "import", rva: 0x1010, indirectCall: true, iatIndex: 2,
    importName: "example.dll!SecondFunction"
  });
});

void test("linkDynamicImportControlTransfers accepts the last complete IAT slot", async () => {
  const linked = await linkDynamicImportControlTransfers(makeTable(), makeCodeFile(),
    rva => rva, { rva: 0x2000, size: 16 }, imports);

  assert.deepEqual(linked.entries[0]?.controlTransfers?.[0], {
    kind: "import", rva: 0x1010, indirectCall: true, iatIndex: 1,
    importName: "example.dll!ExampleFunction"
  });
});

void test("linkDynamicImportControlTransfers rejects an invalid FF opcode", async () => {
  const source = makeTable();
  const bytes = makeCodeFile().data;
  bytes[0x1011] = 0x90;

  const linked = await linkDynamicImportControlTransfers(source,
    new MockFile(bytes), rva => rva, { rva: 0x2000, size: 0x20 }, imports);

  assert.deepEqual(linked, source);
});

void test("linkDynamicImportControlTransfers rejects a truncated REX instruction", async () => {
  const source = makeTable();
  const bytes = makeCodeFile().data.slice(0, 0x1016);

  const linked = await linkDynamicImportControlTransfers(source,
    new MockFile(bytes), rva => rva, { rva: 0x2000, size: 0x20 }, imports);

  assert.deepEqual(linked, source);
});
