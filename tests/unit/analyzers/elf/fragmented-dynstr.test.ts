import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElf } from "../../../../analyzers/elf/index.js";
import { createElfMetadataFile } from "../../../fixtures/elf-metadata-file.js";
import { expectDefined } from "../../../helpers/expect-defined.js";
import { createFileRangeReader } from "../../../../analyzers/file-range-reader.js";
import { createElfRelocationSymbolReader } from "../../../../analyzers/elf/relocation-symbols.js";
import { dynamicRelocationFixture } from "../../../fixtures/elf-dynamic-relocations.js";
import { relocationTable } from "../../../fixtures/elf-relocations.js";

const fragmentedDynamicStrings = async (sections: "omit" | "keep" = "omit") => {
  const { file, expected } = createElfMetadataFile();
  const elf = expectDefined(await parseElf(file));
  const input = new Uint8Array(await file.arrayBuffer());
  const template = expectDefined(elf.programHeaders.find(header => header.type === 1));
  const interpreter = expectDefined(elf.programHeaders.find(header => header.type === 3));
  const dynamic = expectDefined(elf.programHeaders.find(header => header.type === 2));
  const dynstr = expectDefined(elf.sections.find(section => section.name === ".dynstr"));
  const strings = input.subarray(Number(dynstr.offset), Number(dynstr.offset + dynstr.size));
  const bytes = new Uint8Array(0x4000);
  bytes.set(input);
  const view = new DataView(bytes.buffer);
  const phoff = Number(elf.header.phoff);
  const stride = elf.header.phentsize;
  const copyHeader = (source: number, index: number): void => {
    bytes.set(input.subarray(phoff + source * stride, phoff + (source + 1) * stride), phoff + index * stride);
  };
  const writeLoad = (index: number, offset: number, address: bigint): void => {
    const at = phoff + index * stride;
    bytes.fill(0, at, at + stride);
    // Elf64_Phdr, gABI 7.1. The file and virtual addresses are page-aligned.
    view.setUint32(at, 1, true);
    view.setUint32(at + 4, 4, true);
    view.setBigUint64(at + 8, BigInt(offset), true);
    view.setBigUint64(at + 16, address, true);
    view.setBigUint64(at + 32, 0x1000n, true);
    view.setBigUint64(at + 40, 0x1000n, true);
    view.setBigUint64(at + 48, 0x1000n, true);
  };
  copyHeader(interpreter.index, 0);
  writeLoad(1, 0, template.vaddr);
  writeLoad(2, 0x3000, template.vaddr + 0x1000n);
  writeLoad(3, 0x2000, template.vaddr + 0x2000n);
  copyHeader(dynamic.index, 4);
  // Elf64_Ehdr fields from gABI 2.1.
  view.setUint16(56, 5, true);
  if (sections === "omit") {
    view.setBigUint64(40, 0n, true);
    view.setUint16(60, 0, true);
    view.setUint16(62, 0, true);
  }
  // Split the first dependency name after the eighth byte of DT_STRTAB.
  bytes.set(strings.subarray(0, 8), 0x3ff8);
  bytes.set(strings.subarray(8), 0x2000);
  view.setBigUint64(Number(dynamic.offset) + 8, template.vaddr + 0x1ff8n, true);
  bytes[Number(dynstr.offset) + 1] = 0x78; // Give the old physical section a different DT_NEEDED name.
  return { file: new File([bytes], "fragmented-dynstr.elf"), expected };
};

void test("reads a sectionless DT_STRTAB in virtual order across reversed file ranges", async () => {
  const { file, expected } = await fragmentedDynamicStrings();

  const result = expectDefined(await parseElf(file));

  assert.deepEqual(result.issues, []);
  assert.deepEqual(result.dynamic?.issues, []);
  assert.deepEqual(result.dynamic?.needed, expected.needed);
  assert.deepEqual(result.dynSymbols?.issues, []);
  assert.deepEqual(result.dynSymbols?.importSymbols.map(symbol => symbol.name), [expected.importSymbol]);
  assert.deepEqual(result.dynSymbols?.exportSymbols.map(symbol => symbol.name), [expected.exportSymbol]);
});

void test("reports disagreement with a linked string section while reading runtime strings", async () => {
  const { file, expected } = await fragmentedDynamicStrings("keep");

  const result = expectDefined(await parseElf(file));

  assert.deepEqual(result.dynamic?.needed, expected.needed);
  assert.match(result.dynamic?.consistencyIssues?.join(" ") ?? "", /split file ranges.*linked string section/);
  assert.deepEqual(result.dynSymbols?.importSymbols.map(symbol => symbol.name), [expected.importSymbol]);
});

void test("resolves a relocation name split over reversed DT_STRTAB file fragments", async () => {
  const fixture = dynamicRelocationFixture();
  const load = fixture.elf.programHeaders[0]!;
  // DT_STRTAB sits at file offset 384. Split "target" after its first three letters.
  const cut = 388n;
  fixture.bytes.copyWithin(128, Number(cut), 392);
  fixture.elf.programHeaders.push({ ...load, index: 1, offset: 128n, vaddr: load.vaddr + cut,
    filesz: 4n, memsz: 4n });
  load.filesz = cut;
  load.memsz = cut;
  fixture.elf.sections = [];
  const issues: string[] = [];
  const read = createElfRelocationSymbolReader(
    createFileRangeReader(fixture.file(), 0, fixture.bytes.length), fixture.elf, fixture.tags, issues);

  assert.equal((await read(relocationTable({ symbolTableIndex: null }), 1))?.name, "target");
  assert.deepEqual(issues, []);
});
