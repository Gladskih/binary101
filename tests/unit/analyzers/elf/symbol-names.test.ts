import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeElfSymbolNames, getElfSymbolDisplayName, isElfSymbolData } from
  "../../../../analyzers/elf/symbol-names.js";
import { parseElf } from "../../../../analyzers/elf/index.js";
import { parseElfSymbolTables } from "../../../../analyzers/elf/symbol-tables.js";
import { loadItaniumDemangler } from "../../../../analyzers/itanium-demangle/load.node.js";
import { relocationFixture, relocationStorage } from "../../../fixtures/elf-relocations.js";
import { createElfItaniumFile } from "../../../fixtures/elf-itanium-file.js";
import { createElfMetadataFile } from "../../../fixtures/elf-metadata-file.js";
import { renderElfSymbols } from "../../../../renderers/elf/symbols.js";
import { createElfSymbolTableModel } from "../../../../renderers/elf/symbol-tables.js";
import { createElfRelocationTableModel } from "../../../../renderers/elf/relocations.js";

void test("full ELF parsing decodes dynamic symbols and renders both names", async () => {
  const elf = await parseElf(new File([createElfItaniumFile()], "cpp.elf"));
  const symbol = elf?.dynSymbols?.exportSymbols.find(item => item.name === "_Z1fi");

  assert.ok(elf && symbol);
  assert.equal(getElfSymbolDisplayName(symbol), "f(int)");
  assert.equal(symbol.name, "_Z1fi");
  const html: string[] = [];
  renderElfSymbols(elf, html);
  assert.match(html.join(""), /<code>f\(int\)<\/code><br><code class="dim">_Z1fi<\/code>/);
});

void test("ELF imports and exports decode Rust v0 and D with original linker names", async () => {
  const fixture = createElfMetadataFile(undefined, "_RNvC1a4main", "_D3foo3barf");
  const elf = await parseElf(new File([Uint8Array.from(fixture.file.data)], "languages.so"));

  assert.ok(elf?.dynSymbols);
  assert.equal(elf.dynSymbols.importSymbols[0]!.name, "_RNvC1a4main");
  assert.equal(getElfSymbolDisplayName(elf.dynSymbols.importSymbols[0]!), "a::main");
  assert.equal(elf.dynSymbols.exportSymbols[0]!.name, "_D3foo3barf");
  assert.equal(getElfSymbolDisplayName(elf.dynSymbols.exportSymbols[0]!), "float foo.bar");
  assert.equal(isElfSymbolData(elf.dynSymbols.importSymbols[0]!), false);
  assert.equal(isElfSymbolData(elf.dynSymbols.exportSymbols[0]!), true);
});

for (const [name, text] of [["_RNvC1a4main", "a::main"], ["_D3foo3barf", "float foo.bar"]] as const) {
  void test(`ELF static and relocation symbol names include ${name} with raw sorting`, async () => {
    const fixture = relocationFixture();
    fixture.elf.symbolTables = await parseElfSymbolTables(fixture.file(), fixture.elf);
    const entry = fixture.elf.symbolTables[0]!.entries[1]!;
    entry.name = name;
    const reference = { name, value: 0n, sectionIndex: 1 };
    fixture.elf.relocations = { tables: [{ offset: 0, size: 24, entrySize: 24, encoding: "RELA",
      sources: [".rela.text"], sectionIndex: 4, symbolTableIndex: 2, targetSectionIndex: 1 }],
    entries: [{ tableIndex: 0, recordOffset: 0,
      offset: 0n, type: 1, symbolIndex: 1, symbol: reference, addend: 0n, target: null }], issues: [] };

    await decodeElfSymbolNames(fixture.elf, assert.fail);

    assert.equal(getElfSymbolDisplayName(entry), text);
    assert.equal(getElfSymbolDisplayName(reference), text);
    const symbols = createElfSymbolTableModel(fixture.elf.symbolTables[0]!);
    assert.ok(symbols.rowAt(1)!.cells[1]!.html.includes(text));
    assert.equal(symbols.sortValueAt(1, 1), name);
    const relocations = createElfRelocationTableModel(fixture.elf);
    assert.ok(relocations.rowAt(0)!.cells[4]!.html.includes(text));
    assert.equal(relocations.sortValueAt(0, 4), "#1 " + name);
  });
}

void test("static symbols and relocation references share parsing but retain raw sorting", async () => {
  const fixture = relocationFixture();
  fixture.bytes.set(new TextEncoder().encode("\0_Z1fi\0\0"), relocationStorage.strings);
  fixture.elf.symbolTables = await parseElfSymbolTables(fixture.file(), fixture.elf);
  const symbol = { name: "_Z1fi", value: 0n, sectionIndex: 1 };
  fixture.elf.relocations = { tables: [{ offset: 0, size: 24, entrySize: 24, encoding: "RELA",
    sources: [".rela.text"], sectionIndex: 4, symbolTableIndex: 2, targetSectionIndex: 1 }],
  entries: [{ tableIndex: 0, recordOffset: 0, offset: 0n, type: 1, symbolIndex: 1,
    symbol, addend: 0n, target: null }, { tableIndex: 0, recordOffset: 24, offset: 8n,
    type: 0, symbolIndex: null, symbol: null, addend: null, target: null }], issues: [] };
  const api = await loadItaniumDemangler();
  let parses = 0;

  await decodeElfSymbolNames(fixture.elf, async () => ({ ...api, demangleWithText(name) {
    parses += 1;
    return api.demangleWithText(name);
  } }));

  assert.equal(parses, 1);
  assert.equal(getElfSymbolDisplayName(symbol), "f(int)");
  const table = createElfSymbolTableModel(fixture.elf.symbolTables[0]!);
  assert.match(table.rowAt(1)!.cells[1]!.html, /f\(int\)/);
  assert.equal(table.sortValueAt(1, 1), "_Z1fi");
  const relocations = createElfRelocationTableModel(fixture.elf);
  assert.match(relocations.rowAt(0)!.cells[4]!.html, /#1 f\(int\)/);
  assert.equal(relocations.sortValueAt(0, 4), "#1 _Z1fi");
});

void test("empty ELF analysis does not request WASM", async () => {
  await decodeElfSymbolNames(relocationFixture().elf, assert.fail);
  assert.equal(getElfSymbolDisplayName({ name: "raw" }), "raw");
});

void test("ELF loader failures preserve symbol records and warn once", async () => {
  const elf = (await parseElf(new File([createElfItaniumFile()], "cpp.elf")))!;
  const imported = { ...elf.dynSymbols!.exportSymbols[0]!, name: "_Z1fv" };
  elf.dynSymbols!.importSymbols = [imported];
  elf.dynSymbols!.exportSymbols = [{ ...imported, name: "_Z1fi" }];
  const existingIssues = [...elf.issues];

  await decodeElfSymbolNames(elf, () => Promise.reject(new Error("offline")));

  assert.equal(getElfSymbolDisplayName(imported), "_Z1fv");
  assert.equal(getElfSymbolDisplayName(elf.dynSymbols!.exportSymbols[0]!), "_Z1fi");
  assert.deepEqual(elf.issues, [...existingIssues, "ELF symbol demangling unavailable: offline"]);
});
