import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElfLsda } from "../../../../analyzers/elf/lsda.js";
import { relocationFixture, relocationSection } from "../../../fixtures/elf-relocations.js";

const fixture = (bytes: number[]) => {
  const source = relocationFixture();
  source.bytes.set(bytes, 64);
  source.elf.sections.push(relocationSection(4, { name: ".gcc_except_table", type: 1,
    offset: 64n, addr: 8192n, size: BigInt(bytes.length) }));
  source.elf.unwind = [{ sectionIndex: 1, cies: [], issues: [], fdes: [{ offset: 0, cieOffset: 0,
    start: { address: 4096n, indirect: false }, range: 32n,
    lsda: { address: 8192n, indirect: false }, instructions: [] }] }];
  return source;
};

void test("decodes LSDA call sites and cleanup action records", async () => {
  // omit LPStart, omit type table, ULEB call-site encoding, four-byte call-site table.
  const source = fixture([255, 255, 1, 4, 2, 5, 12, 1, 0, 0]);
  const parsed = await parseElfLsda(source.file(), source.elf);
  assert.deepEqual(parsed[0]?.callSites, [{ start: 2n, length: 5n, landingPad: 12n, action: 1n }]);
  assert.deepEqual(parsed[0]?.actions, [{ offset: 8, typeFilter: 0n, nextOffset: 0n }]);
  assert.deepEqual(parsed[0]?.issues, []);
});

void test("reports invalid table lengths, missing bytes and cyclic actions", async () => {
  const short = fixture([255, 255, 1, 9, 2]);
  assert.match((await parseElfLsda(short.file(), short.elf))[0]!.issues.join(" "), /truncated/);
  const cycle = fixture([255, 255, 1, 4, 2, 5, 12, 1, 0, 127]);
  assert.match((await parseElfLsda(cycle.file(), cycle.elf))[0]!.issues.join(" "), /cycle/);
});

void test("reads fixed-width reverse type entries including catch-all null pointers", async () => {
  const source = fixture([255, 3, 11, 1, 4, 2, 5, 12, 1, 1, 0, 0, 0, 0, 0]);
  // Type base is 14 (offset 3 + 11); place a zero word there, ending at 14.
  source.bytes[74] = 0;
  const result = (await parseElfLsda(source.file(), source.elf))[0]!;
  assert.equal(result.types[0]?.index, 1n);
  assert.equal(result.types[0]?.pointer?.address, 0n);
});

void test("deduplicates descriptors and bounds each at the next LSDA address", async () => {
  const source = fixture([255, 255, 1, 9, 2, 255, 255, 1, 0]);
  const first = source.elf.unwind![0]!.fdes[0]!;
  source.elf.unwind![0]!.fdes.push(first, { ...first, lsda: { address: 8197n, indirect: false } });
  const result = await parseElfLsda(source.file(), source.elf);
  assert.equal(result.length, 2);
  assert.match(result[0]!.issues.join(" "), /truncated/);
  assert.deepEqual(result[1]!.issues, []);
});

void test("reports indirect or unsupported storage and missing bytes", async () => {
  const source = fixture([]);
  assert.match((await parseElfLsda(source.file(), source.elf))[0]!.issues.join(" "), /direct pointer/);
  source.elf.sections[4]!.size = 8n;
  source.elf.sections[4]!.offset = 1n << 60n;
  assert.match((await parseElfLsda(source.file(), source.elf))[0]!.issues.join(" "), /outside/);
  source.elf.unwind = [];
  assert.deepEqual(await parseElfLsda(source.file(), source.elf), []);
});

void test("reads explicit landing pad base and validates type table offsets", async () => {
  const source = fixture([3, 0, 16, 0, 0, 255, 1, 0]);
  assert.deepEqual((await parseElfLsda(source.file(), source.elf))[0]?.landingPadBase,
    { address: 4096n, indirect: false });
  source.bytes.set([255, 3, 127], 64);
  assert.match((await parseElfLsda(source.file(), source.elf))[0]!.issues.join(" "), /type table/);
});

void test("stops on truncated headers and invalid call-site pointers", async () => {
  const source = fixture([255]);
  assert.ok((await parseElfLsda(source.file(), source.elf))[0]!.issues.length > 0);
  source.elf.sections[4]!.size = 5n;
  source.bytes.set([255, 255, 0x11, 1, 0], 64);
  assert.match((await parseElfLsda(source.file(), source.elf))[0]!.issues.join(" "), /encoding/);
  source.elf.sections[4]!.flags = 0x800n;
  assert.match((await parseElfLsda(source.file(), source.elf))[0]!.issues.join(" "), /uncompressed/);
});

void test("sorts descriptor boundaries independently of FDE order and ignores null pointers", async () => {
  const source = fixture([255, 255, 1, 0, 255, 255, 1, 0]);
  const first = source.elf.unwind![0]!.fdes[0]!;
  source.elf.unwind![0]!.fdes = [{ ...first, lsda: { address: 8196n, indirect: false } },
    { ...first, lsda: null }, { ...first, lsda: { address: 0n, indirect: false } }, first];
  const result = await parseElfLsda(source.file(), source.elf);
  assert.deepEqual(result.map(item => item.address), [8192n, 8196n]);
  assert.deepEqual(result.flatMap(item => item.issues), []);
});

void test("selects only a containing exception section and preserves big endian addresses", async () => {
  const source = fixture([3, 0, 0, 16, 0, 255, 1, 0]);
  source.elf.littleEndian = false;
  assert.equal((await parseElfLsda(source.file(), source.elf))[0]?.landingPadBase?.address, 4096n);
  source.elf.sections[4]!.name = ".data";
  assert.match((await parseElfLsda(source.file(), source.elf))[0]!.issues.join(" "), /gcc_except_table/);
  source.elf.sections[4]!.name = ".gcc_except_table";
  source.elf.sections[4]!.addr = 8193n;
  assert.match((await parseElfLsda(source.file(), source.elf))[0]!.issues.join(" "), /direct/);
});
