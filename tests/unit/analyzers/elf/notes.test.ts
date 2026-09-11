"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElf } from "../../../../analyzers/elf/index.js";
import { parseElfNotes } from "../../../../analyzers/elf/notes.js";
import type { ElfProgramHeader, ElfSectionHeader } from "../../../../analyzers/elf/types.js";
import { createElfMetadataFile } from "../../../fixtures/elf-metadata-file.js";
import { MockFile } from "../../../helpers/mock-file.js";

const makeSection = (partial: Partial<ElfSectionHeader>): ElfSectionHeader =>
  ({
    nameOff: 0,
    type: 0,
    typeName: null,
    flags: 0n,
    flagNames: [],
    addr: 0n,
    offset: 0n,
    size: 0n,
    link: 0,
    info: 0,
    addralign: 0n,
    entsize: 0n,
    index: 0,
    ...partial
  }) as ElfSectionHeader;

void test("decodes CORE descriptors only with explicit core ABI context", async () => {
  const bytes = new Uint8Array(36);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, 5, true);
  view.setUint32(4, 16, true);
  view.setUint32(8, 6, true); // NT_AUXV, two zero words form AT_NULL in ELF64.
  bytes.set(new TextEncoder().encode("CORE\0"), 12);
  const file = new File([bytes], "core-note");
  const sections = [makeSection({ type: 7, size: 36n })];
  const plain = await parseElfNotes({ file, sections, programHeaders: [], littleEndian: true });
  assert.equal(plain?.entries[0]?.core, undefined);
  const core = await parseElfNotes({ file, sections, programHeaders: [],
    littleEndian: true, is64: true, coreMachine: 62 });
  assert.equal(core?.entries[0]?.typeName, "NT_AUXV");
  assert.deepEqual(core?.entries[0]?.core?.auxv, [{ tag: 0n, value: 0n }]);
});

void test("parseElfNotes decodes GNU build-id", async () => {
  const { file, expected } = createElfMetadataFile();
  const parsed = await parseElf(file);
  assert.ok(parsed?.notes);
  const buildId = parsed.notes.entries.find(entry => entry.typeName === "NT_GNU_BUILD_ID");
  assert.ok(buildId);
  assert.equal(buildId.value, expected.buildIdHex);
});

void test("parseElfNotes reports truncated note payloads", async () => {
  const namesz = 4;
  const descsz = 32;
  const bytes = new Uint8Array(12 + namesz + 4).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(0, namesz, true);
  dv.setUint32(4, descsz, true);
  dv.setUint32(8, 3, true);
  bytes.set(new TextEncoder().encode("GNU\0"), 12);
  const file = new MockFile(bytes, "note.bin", "application/x-elf");
  const sections: ElfSectionHeader[] = [makeSection({ type: 7, name: ".note.gnu.build-id", offset: 0n, size: BigInt(bytes.length), index: 0 })];

  const notes = await parseElfNotes({ file, programHeaders: [] as ElfProgramHeader[], sections, littleEndian: true });
  assert.ok(notes);
  assert.ok(notes.issues.some(issue => issue.includes("truncated")));
});

void test("parseElfNotes deduplicates notes when PT_NOTE overlaps SHT_NOTE ranges", async () => {
  const bytes = new Uint8Array(0x40).fill(0);
  const dv = new DataView(bytes.buffer);

  dv.setUint32(0x00, 4, true);
  dv.setUint32(0x04, 4, true);
  dv.setUint32(0x08, 3, true);
  bytes.set(new TextEncoder().encode("GNU\0"), 0x0c);
  bytes.set([0x11, 0x22, 0x33, 0x44], 0x10);

  dv.setUint32(0x14, 4, true);
  dv.setUint32(0x18, 16, true);
  dv.setUint32(0x1c, 1, true);
  bytes.set(new TextEncoder().encode("GNU\0"), 0x20);
  dv.setUint32(0x24, 0, true);
  dv.setUint32(0x28, 1, true);
  dv.setUint32(0x2c, 2, true);
  dv.setUint32(0x30, 3, true);

  const file = new MockFile(bytes, "overlap-notes.bin", "application/x-elf");
  const notes = await parseElfNotes({
    file,
    programHeaders: [
      {
        type: 4,
        typeName: "PT_NOTE",
        offset: 0n,
        vaddr: 0n,
        paddr: 0n,
        filesz: 0x34n,
        memsz: 0x34n,
        flags: 0,
        flagNames: [],
        align: 4n,
        index: 0
      } as ElfProgramHeader
    ],
    sections: [
      makeSection({ type: 7, name: ".note.gnu.build-id", offset: 0n, size: 0x14n, index: 0 }),
      makeSection({ type: 7, name: ".note.gnu.abi-tag", offset: 0x14n, size: 0x20n, index: 1 })
    ],
    littleEndian: true
  });

  assert.ok(notes);
  assert.equal(notes.entries.length, 2);
  assert.equal(
    notes.entries.filter(entry => entry.typeName === "NT_GNU_BUILD_ID").length,
    1
  );
});
void test("rejects note ranges outside the file or safe integer space", async () => {
  const parsed = await parseElfNotes({ file: new File([new Uint8Array(16)], "note-ranges"),
    programHeaders: [], littleEndian: true, sections: [
      makeSection({ type: 7, offset: 1n << 60n, size: 16n }),
      makeSection({ type: 7, offset: 0n, size: 1n << 60n }),
      makeSection({ type: 7, offset: 16n, size: 16n })
    ] });
  assert.deepEqual(parsed?.entries, []);
  assert.equal(parsed?.issues.filter(issue => issue.includes("too large")).length, 2);
  assert.match(parsed!.issues.join(" "), /outside the file/);
});

const bigEndianNotes = (): File => {
  // A GNU build ID with padding, followed by an empty 12-byte note header (gABI notes).
  const bytes = new Uint8Array(32);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, 4, false);
  view.setUint32(4, 3, false);
  view.setUint32(8, 3, false);
  bytes.set([71, 78, 85, 0, 0xab, 0xcd, 0xef, 0], 12);
  return new File([bytes], "big-endian-notes");
};

void test("preserves complete note records, padding and empty headers at the exact boundary", async () => {
  const parsed = await parseElfNotes({ file: bigEndianNotes(), programHeaders: [], littleEndian: false,
    sections: [makeSection({ type: 7, size: 32n, index: 7 }),
      makeSection({ type: 7, size: 32n, name: "duplicate" }), makeSection({ type: 1, size: 32n })] });
  assert.deepEqual(parsed, { issues: [], entries: [
    { source: "SHT_NOTE section #7", name: "GNU", type: 3, typeName: "NT_GNU_BUILD_ID",
      description: "GNU build ID", value: "abcdef", descSize: 3 },
    { source: "SHT_NOTE section #7", name: "", type: 0, typeName: null,
      description: null, value: null, descSize: 0 }
  ] });
});

const noteSegment = (type: number, filesz: bigint): ElfProgramHeader => ({
  type, filesz, index: 5, typeName: null, offset: 0n, vaddr: 0n, paddr: 0n,
  memsz: filesz, flags: 4, flagNames: [], align: 4n
});

void test("discovers notes through program headers and ignores unrelated or empty ranges", async () => {
  const parsed = await parseElfNotes({ file: bigEndianNotes(), sections: [], littleEndian: false,
    programHeaders: [noteSegment(4, 32n), noteSegment(1, 20n), noteSegment(4, 0n)] });
  assert.equal(parsed?.entries.length, 2);
  assert.equal(parsed?.entries[0]?.source, "PT_NOTE segment #5");
  assert.deepEqual(parsed?.issues, []);
  assert.equal(await parseElfNotes({ file: bigEndianNotes(), littleEndian: false,
    programHeaders: [noteSegment(1, 32n)], sections: [makeSection({ type: 7, size: 0n })] }), null);
});

void test("reports truncated names, preserves exact-end names and warns about clipped ranges", async () => {
  const bytes = new Uint8Array(16);
  new DataView(bytes.buffer).setUint32(0, 4, true);
  bytes.set([65, 66, 67, 68], 12);
  const exact = await parseElfNotes({ file: new File([bytes], "exact"), littleEndian: true,
    programHeaders: [], sections: [makeSection({ type: 7, size: 16n, name: "exact" })] });
  assert.equal(exact?.entries[0]?.name, "ABCD");
  assert.equal(exact?.entries[0]?.source, "Section \"exact\"");
  assert.deepEqual(exact?.issues, []);
  const clipped = await parseElfNotes({ file: new File([bytes.subarray(0, 15)], "clipped"),
    littleEndian: true, programHeaders: [], sections: [makeSection({ type: 7, size: 16n })] });
  assert.deepEqual(clipped?.entries, []);
  assert.equal(clipped?.issues.length, 2);
  assert.match(clipped!.issues.join(" "), /note name is truncated/);
});
