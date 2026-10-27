import assert from "node:assert/strict";
import { test } from "node:test";
import { collectEhFunctionSymbols } from "../../../../../analyzers/pe/msvc-eh/symbols.js";
import { createEhFixture } from "../../../../fixtures/pe-msvc-eh.js";
import type { CoffDebugInfo } from "../../../../../analyzers/coff/debug-types.js";
import type { PeLegacyCodeViewInfo } from "../../../../../analyzers/pe/debug/legacy-codeview.js";

const coffInfo = (): CoffDebugInfo => ({ source: "coff-header", symbolTableOffset: 0,
  stringTableOffset: null, lineNumberBlocks: [], symbols: [{ index: 0, name: "__GSHandlerCheck_EH4",
    nameSource: "short", value: 0, sectionNumber: 1, type: 0x20, storageClass: 2,
    auxiliarySymbolCount: 0, auxiliaryRecords: [] }] });

const codeViewInfo = (): PeLegacyCodeViewInfo => ({ signature: "NB09", directories: [{ flags: 0,
  subsections: [{ type: 0x124, module: 1, offset: 0, size: 40, data: { kind: "symbols", records: [
    { type: 0x1110, name: "__GSHandlerCheck_EH4", procedure: { referenceKind: "typeIndex",
      codeLength: 16, storedLocation: { segment: 1, offset: 0 } } }
  ] } }] }] });

void test("EH identity can use mapped COFF function symbols and resolved C7 procedures", () => {
  const fixture = createEhFixture().builder.build();
  const symbols = collectEhFunctionSymbols(fixture.core, [coffInfo()], [codeViewInfo()], []);
  assert.equal(symbols.length, 2);
  assert.deepEqual(symbols.map(symbol => symbol.rva), [0x1000, 0x1000]);
});

void test("EH symbol identity rejects OMAP, data symbols, unresolved names and discarded procedures", () => {
  const fixture = createEhFixture().builder.build();
  assert.deepEqual(collectEhFunctionSymbols(fixture.core, [coffInfo()], [codeViewInfo()], [{ type: 7 }]), []);
  const coff = coffInfo();
  coff.symbols[0]!.type = 0;
  const codeview = codeViewInfo();
  codeview.directories[0]!.subsections = [];
  assert.deepEqual(collectEhFunctionSymbols(fixture.core, [coff], [codeview], []), []);
});

for (const patch of [{ sectionNumber: 0 }, { nameSource: "unresolved" as const }, { value: -1 },
  { value: 0xffffffff }, { name: "unrelated" }]) {
  void test(`COFF identity rejects ${JSON.stringify(patch)}`, () => {
    const fixture = createEhFixture().builder.build();
    const coff = coffInfo();
    Object.assign(coff.symbols[0]!, patch);
    assert.deepEqual(collectEhFunctionSymbols(fixture.core, [coff], [], []), []);
  });
}

void test("COFF name decoration is removed only for I386 function symbols", () => {
  const fixture = createEhFixture().builder.build();
  fixture.core.coff.Machine = 0x14c;
  const coff = coffInfo();
  coff.symbols[0]!.name = "___CxxFrameHandler3";
  assert.equal(collectEhFunctionSymbols(fixture.core, [coff], [], [])[0]?.name, "__CxxFrameHandler3");
  fixture.core.sections[0]!.characteristics = 0;
  assert.deepEqual(collectEhFunctionSymbols(fixture.core, [coff], [], []), []);
});

void test("CodeView rejects unknown signatures and nonprocedure records", () => {
  const fixture = createEhFixture().builder.build();
  const info = codeViewInfo();
  info.signature = "NB04";
  assert.deepEqual(collectEhFunctionSymbols(fixture.core, [], [info], []), []);
  info.directories[0]!.subsections.push({ type: 0x120, module: 1, offset: 0, size: 0 });
  info.directories[0]!.subsections.push({ type: 0x124, module: 1, offset: 0, size: 0,
    data: { kind: "symbols", records: [{ type: 0x1110 }, { type: 0x1110, name: "unrelated" }] } });
  assert.deepEqual(collectEhFunctionSymbols(fixture.core, [], [info], [{ type: 8 }]), []);
});

void test("COFF procedure offsets and zero VirtualSize retain exact section bounds", () => {
  const fixture = createEhFixture().builder.build();
  const coff = coffInfo();
  coff.symbols[0]!.value = 16;
  fixture.core.sections[0]!.virtualSize = 0;
  assert.equal(collectEhFunctionSymbols(fixture.core, [coff], [], [])[0]?.rva, 0x1010);
  coff.symbols[0]!.value = fixture.core.sections[0]!.sizeOfRawData;
  assert.deepEqual(collectEhFunctionSymbols(fixture.core, [coff], [], []), []);
});

void test("OMAP_FROM_SRC prevents both COFF and otherwise resolvable CodeView identities", () => {
  const fixture = createEhFixture().builder.build();
  assert.deepEqual(collectEhFunctionSymbols(fixture.core, [coffInfo()], [codeViewInfo()], [{ type: 8 }]), []);
});
