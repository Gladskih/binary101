import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElf } from "../../../../analyzers/elf/index.js";
import { createElfMetadataFile } from "../../../fixtures/elf-metadata-file.js";
import { expectDefined } from "../../../helpers/expect-defined.js";

const dynamicFixture = async () => {
  const { file, expected } = createElfMetadataFile();
  const parsed = expectDefined(await parseElf(file));
  const dynamic = expectDefined(parsed.sections.find(section => section.type === 6)); // SHT_DYNAMIC
  const bytes = await file.arrayBuffer();
  return { parsed, dynamic, expected, view: new DataView(bytes),
    file: () => new File([bytes], file.name) };
};

void test("uses DT_STRSZ to bound runtime symbol names and reports conflicting section size", async () => {
  const fixture = await dynamicFixture();
  const strings = fixture.parsed.sections[fixture.dynamic.link]!;
  // Fixture's second Elf64_Dyn entry is DT_STRSZ, d_val at +8.
  const size = strings.size - BigInt(fixture.expected.exportSymbol.length + 1);
  fixture.view.setBigUint64(Number(fixture.dynamic.offset) + 16 + 8, size, true);
  // Replace DT_INIT with DT_SYMTAB pointing to the same table as the section.
  const symbolTag = Number(fixture.dynamic.offset) + 6 * 16;
  fixture.view.setBigInt64(symbolTag, 6n, true);
  fixture.view.setBigUint64(symbolTag + 8, fixture.parsed.sections[3]!.addr, true);

  const parsed = expectDefined(await parseElf(fixture.file()));

  assert.deepEqual(parsed.dynamic?.consistencyIssues,
    [`DT_STRSZ (${size} bytes) disagrees with linked string section #${strings.index} sh_size (${strings.size} bytes).`]);
  assert.deepEqual(parsed.dynamic?.needed, fixture.expected.needed);
  assert.equal(parsed.dynSymbols?.exportSymbols.length, 0);
  assert.equal(parsed.dynSymbols?.importSymbols[0]?.name, fixture.expected.importSymbol);
});

void test("warns when DT_STRTAB points past the start of its linked string section", async () => {
  const fixture = await dynamicFixture();
  const strings = fixture.parsed.sections[fixture.dynamic.link]!;
  // The first entry is DT_STRTAB; file offset and VA advance together in the fixture's PT_LOAD.
  fixture.view.setBigUint64(Number(fixture.dynamic.offset) + 8, strings.addr + 1n, true);

  const parsed = expectDefined(await parseElf(fixture.file()));

  const issues = parsed.dynamic?.consistencyIssues?.join(" ") ?? "";
  assert.match(issues, /DT_STRTAB.*sh_addr/);
  assert.match(issues, /DT_STRTAB.*different file offset/);
});

void test("keeps section symbol names when DT_SYMTAB points at a different table", async () => {
  const fixture = await dynamicFixture();
  const strings = fixture.parsed.sections[fixture.dynamic.link]!;
  // Reuse the Elf64_Dyn DT_INIT slot for a conflicting DT_SYMTAB (gABI 8.3).
  const entry = Number(fixture.dynamic.offset) + 6 * 16;
  fixture.view.setBigInt64(entry, 6n, true);
  fixture.view.setBigUint64(entry + 8, strings.addr, true);
  fixture.view.setBigUint64(Number(fixture.dynamic.offset) + 16 + 8, strings.size - 8n, true);

  const parsed = expectDefined(await parseElf(fixture.file()));

  assert.match(parsed.dynamic?.consistencyIssues?.join(" ") ?? "", /DT_SYMTAB.*SHT_DYNSYM/);
  assert.equal(parsed.dynSymbols?.exportSymbols[0]?.name, fixture.expected.exportSymbol);
});

void test("rejects competing DT_STRSZ values instead of choosing one arbitrarily", async () => {
  const fixture = await dynamicFixture();
  // Replace DT_INIT with a duplicate DT_STRSZ carrying a conflicting value.
  const entry = Number(fixture.dynamic.offset) + 6 * 16;
  fixture.view.setBigInt64(entry, 10n, true);
  fixture.view.setBigUint64(entry + 8, 1n, true);

  const parsed = expectDefined(await parseElf(fixture.file()));

  assert.deepEqual(parsed.dynamic?.issues, ["Conflicting DT_STRTAB or DT_STRSZ values."]);
  assert.equal(parsed.dynamic?.consistencyIssues, undefined);
  assert.deepEqual(parsed.dynamic?.needed, fixture.expected.needed);
});

void test("reports a section that ends before the dynamic segment's terminator", async () => {
  const fixture = await dynamicFixture();
  // Elf64_Shdr.sh_size at +32; omit the final DT_NULL record from the section only.
  const offset = Number(fixture.parsed.header.shoff) + fixture.dynamic.index * 64 + 32;
  fixture.view.setBigUint64(offset, fixture.dynamic.size - 16n, true);

  const parsed = expectDefined(await parseElf(fixture.file()));

  assert.match(parsed.dynamic?.consistencyIssues?.join(" ") ?? "", /DT_NULL beyond.*sh_size/);
  assert.equal(parsed.dynamic?.terminated, true);
});

for (const [fieldOffset, fieldName] of [
  [8, "p_offset"], [16, "p_vaddr"], [32, "p_filesz"], [40, "p_memsz"]
] as const) {
  void test(`reports when PT_DYNAMIC ${fieldName} disagrees with SHT_DYNAMIC`, async () => {
    const fixture = await dynamicFixture();
    const program = expectDefined(fixture.parsed.programHeaders.find(header => header.type === 2));
    // Elf64_Phdr offsets from gABI 7.1.
    const offset = Number(fixture.parsed.header.phoff) + program.index * 56 + fieldOffset;
    const original = fixture.view.getBigUint64(offset, true);
    fixture.view.setBigUint64(offset, original - 16n, true);

    const parsed = expectDefined(await parseElf(fixture.file()));

    assert.match(parsed.dynamic?.consistencyIssues?.join(" ") ?? "", new RegExp(`PT_DYNAMIC.*${fieldName}`));
  });
}

void test("accepts padding after a complete section in the PT_DYNAMIC segment", async () => {
  const fixture = await dynamicFixture();
  const program = expectDefined(fixture.parsed.programHeaders.find(header => header.type === 2));
  const offset = Number(fixture.parsed.header.phoff) + program.index * 56;
  // A full entry of padding after DT_NULL does not affect the dynamic data.
  fixture.view.setBigUint64(offset + 32, program.filesz + 16n, true);
  fixture.view.setBigUint64(offset + 40, program.memsz + 16n, true);

  const parsed = expectDefined(await parseElf(fixture.file()));

  assert.equal(parsed.dynamic?.consistencyIssues, undefined);
  assert.deepEqual(parsed.dynamic?.needed, fixture.expected.needed);
});
