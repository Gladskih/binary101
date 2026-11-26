import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElf } from "../../../../analyzers/elf/index.js";
import { parseElfSFrame } from "../../../../analyzers/elf/sframe.js";
import { relocationFixture, relocationSection } from "../../../fixtures/elf-relocations.js";
import { sframeElf, sframePayload } from "../../../fixtures/elf-sframe.js";
import { MockFile } from "../../../helpers/mock-file.js";

const parse = (payload: Uint8Array, little = true, source = "both") =>
  parseElf(new File([sframeElf(payload, little, source)], "sframe.elf"));

const readShortSFrame = async (bytes: Uint8Array, readableBytes: number) => {
  const file = new class extends MockFile {
    override slice(start = 0, end = this.size, contentType?: string): Blob {
      return super.slice(start, Math.min(end, readableBytes), contentType);
    }
  }(bytes);
  const { elf } = relocationFixture();
  elf.sections = [relocationSection(1, { name: ".sframe", size: BigInt(file.size) })];
  return (await parseElfSFrame(file, elf))[0];
};

void test("reports a short SFrame descriptor read after validating its file range", async () => {
  const { bytes, descriptorStart } = sframePayload(3);
  const table = await readShortSFrame(bytes, descriptorStart + 4);
  assert.deepEqual(table?.functions, []);
  assert.equal(table?.issues[0], "Truncated SFrame function descriptor.");
});

void test("reports a short SFrame attribute read after validating its row block", async () => {
  const { bytes, rowStart } = sframePayload(3);
  const table = await readShortSFrame(bytes, rowStart + 2);
  assert.equal(table?.functions[0]?.attributes, undefined);
  assert.deepEqual(table?.functions[0]?.issues, ["Truncated SFrame function attributes."]);
  assert.deepEqual(table?.rows, []);
});

for (const [version, little, source] of [[1, true, "both"], [2, false, "segment"],
  [3, true, "both"]] as const) {
  void test(`decodes SFrame v${version} from ${source} in ELF byte order`, async () => {
    const elf = await parse(sframePayload(version, little, 2).bytes, little, source);
    assert.ok(elf && "sframe" in elf, "missing SFrame analysis");
    const [table, duplicate] = elf.sframe!;
    assert.equal(duplicate, undefined);
    assert.equal(table?.preamble?.version, version);
    assert.deepEqual(table?.issues, []);
    assert.deepEqual(table?.functions.map(entry => entry.issues), [[], []]);
    assert.equal(table?.address, 0x402000n);
    assert.deepEqual(table?.functions.map(entry => entry.startOffset),
      version === 1 ? [-4096n, -4064n] : version === 2 ? [-4128n, -4116n] : [-4128n, -4112n]);
    assert.deepEqual(table?.rows.map(row => [row.functionIndex, row.pcOffset, row.words]),
      [[0, 4, [32, -8, -16]], [1, 4, [32, -8, -16]]]);
  });
}

void test("recognizes the historical PROGBITS .sframe convention", async () => {
  const payload = sframePayload(1);
  const { elf } = relocationFixture();
  elf.sections = [relocationSection(1, { name: ".sframe", size: BigInt(payload.bytes.length) })];
  const [table] = await parseElfSFrame(new File([payload.bytes], "sframe.bin"), elf);
  assert.equal(table?.preamble?.version, 1);
  assert.deepEqual(table?.issues, []);
  assert.equal(table?.functions.length, 1);
});

void test("decodes identical SFrame segments only once", async () => {
  const bytes = sframeElf(sframePayload(3).bytes, true, "segment");
  // ELF64 e_phnum at +56 and two 56-byte entries starting at +64 (ELF gABI §2 and §7).
  new DataView(bytes.buffer).setUint16(56, 2, true);
  bytes.copyWithin(120, 64, 120);
  const elf = await parseElf(new File([bytes], "duplicate-segments.elf"));
  assert.equal(elf?.sframe?.length, 1);
  assert.deepEqual(elf.sframe[0]?.source, { programHeaderIndex: 0 });
});

void test("retains descriptors for separate SFrame virtual addresses", async () => {
  const bytes = sframeElf(sframePayload(3).bytes, true, "segment");
  const view = new DataView(bytes.buffer);
  view.setUint16(56, 2, true);
  bytes.copyWithin(120, 64, 120);
  // p_vaddr at +16 in the second Elf64_Phdr, ELF gABI §7.
  view.setBigUint64(136, 0x502000n, true);
  const elf = await parseElf(new File([bytes], "two-sframe-mappings.elf"));
  assert.deepEqual(elf?.sframe?.map(table => table.address), [0x402000n, 0x502000n]);
});

void test("ignores PROGBITS with another name and a non-SFrame segment", async () => {
  const payload = sframePayload(1);
  const { elf } = relocationFixture();
  elf.sections = [relocationSection(1, { name: ".data", size: BigInt(payload.bytes.length) }),
    relocationSection(2, { name: ".sframe", type: 8, size: BigInt(payload.bytes.length) })];
  const bytes = sframeElf(payload.bytes, true, "segment");
  new DataView(bytes.buffer).setUint32(64, 1, true); // PT_LOAD from ELF gABI §7.
  const file = new File([bytes], "unrelated.elf");
  assert.deepEqual(await parseElfSFrame(file, elf), []);
  assert.equal((await parseElf(file))?.sframe, undefined);
});

void test("preserves a relocatable function's encoded offset without an address", async () => {
  const elf = await parse(sframePayload(3).bytes, true, "object");
  assert.ok(elf && "sframe" in elf, "missing SFrame analysis");
  assert.equal(elf.sframe?.[0]?.address, null);
  assert.equal(elf.sframe?.[0]?.functions[0]?.startOffset, -4128n);
});

void test("preserves an unknown SFrame version and stops at the preamble", async () => {
  const payload = sframePayload(3);
  payload.bytes[2] = 255;
  const elf = await parse(payload.bytes.subarray(0, 4));
  assert.ok(elf && "sframe" in elf, "missing SFrame analysis");
  assert.equal(elf.sframe?.[0]?.preamble?.version, 255);
  assert.match(elf.sframe?.[0]?.issues.join(" ") ?? "", /Unsupported SFrame version/);
  assert.deepEqual(elf.sframe?.[0]?.functions, []);
});

void test("does not let a malformed frame row consume the next function's data", async () => {
  const payload = sframePayload(3, true, 2);
  // FRE data word size 4 with three operands cannot fit in the first function's block.
  payload.bytes[payload.rowStart + 7] = 0x47;
  const elf = await parse(payload.bytes);
  assert.ok(elf && "sframe" in elf, "missing SFrame analysis");
  assert.match(elf.sframe?.[0]?.functions[0]?.issues.join(" ") ?? "", /Truncated frame row/);
  assert.deepEqual(elf.sframe?.[0]?.rows.map(row => row.functionIndex), [1]);
});

void test("decodes rows in storage order and preserves their descriptor association", async () => {
  const payload = sframePayload(3, true, 2);
  // The indices remain sorted by PC, but the first points to the later row block.
  payload.view.setUint32(payload.descriptorStart + 12, 11, true);
  payload.view.setUint32(payload.descriptorStart + 16 + 12, 0, true);
  payload.view.setUint16(payload.rowStart + 5, 12, true);
  const table = (await parse(payload.bytes))?.sframe?.[0];
  assert.deepEqual(table?.rows.map(row => [row.functionIndex, row.pcOffset]), [[1, 12], [0, 4]]);
  assert.deepEqual(table?.issues, []);
});

void test("does not read SFrame attributes across a following block", async () => {
  const fixture = sframePayload(3, true, 2);
  fixture.view.setUint32(fixture.descriptorStart + 12, 9, true);
  const table = (await parse(fixture.bytes))?.sframe?.[0];
  assert.deepEqual(table?.functions[0]?.issues, ["Truncated SFrame function attributes."]);
  assert.deepEqual(table?.rows.map(row => row.functionIndex), [1]);
});

void test("accepts an undefined return address row with no data words", async () => {
  const fixture = sframePayload(3);
  fixture.view.setUint32(16, 8, true); // Five attribute bytes, two-byte PC offset and row info.
  fixture.view.setUint8(fixture.rowStart + 7, 0);
  const table = (await parse(fixture.bytes.subarray(0, fixture.rowStart + 8)))?.sframe?.[0];
  assert.deepEqual(table?.rows[0]?.words, []);
  assert.deepEqual(table?.issues, []);
});

void test("reads attributes ending exactly at the end of an empty frame block", async () => {
  const fixture = sframePayload(3);
  fixture.view.setUint32(12, 0, true);
  fixture.view.setUint32(16, 5, true);
  fixture.view.setUint16(fixture.rowStart, 0, true);
  const table = (await parse(fixture.bytes.subarray(0, fixture.rowStart + 5)))?.sframe?.[0];
  assert.equal(table?.functions[0]?.attributes?.rowCount, 0);
  assert.deepEqual(table?.functions[0]?.issues, []);
});

for (const [title, alter, issue] of [
  ["preamble", (bytes: Uint8Array) => bytes.subarray(0, 3), /Truncated SFrame preamble/],
  ["header", (bytes: Uint8Array) => bytes.subarray(0, 27), /Truncated SFrame header/],
  ["magic", (bytes: Uint8Array) => { bytes[0] = 0; return bytes; }, /Invalid SFrame magic/],
  ["area", (bytes: Uint8Array) => bytes.subarray(0, -1), /areas overlap or extend/],
  ["descriptor overlap", (bytes: Uint8Array) => {
    new DataView(bytes.buffer).setUint32(8, 2, true);
    return bytes;
  }, /areas overlap or extend/],
  ["descriptor count", (bytes: Uint8Array) => {
    new DataView(bytes.buffer).setUint32(8, 0xffffffff, true);
    return bytes;
  }, /areas overlap or extend/]
] as const) {
  void test(`validates SFrame ${title} before reading descriptors`, async () => {
    const table = (await parse(alter(sframePayload(3).bytes)))?.sframe?.[0];
    assert.match(table?.issues.join(" ") ?? "", issue);
    assert.deepEqual(table?.functions, []);
  });
}

for (const [label, offset, value, issue] of [
  ["attributes outside", 44, 11, /outside the FRE area/],
  ["truncated attributes", 44, 10, /Truncated SFrame function attributes/],
  ["PC width", 50, 15, /Invalid SFrame frame row PC width/],
  ["data width", 55, 0x67, /Invalid SFrame frame row data width/]
] as const) {
  void test(`validates SFrame ${label}`, async () => {
    const payload = sframePayload(3);
    payload.bytes[offset] = value;
    const table = (await parse(payload.bytes))?.sframe?.[0];
    assert.match(table?.functions[0]?.issues.join(" ") ?? "", issue);
    assert.match(table?.issues[0] ?? "", /declares 1 frame rows; decoded 0/);
  });
}

void test("retains a valid frame row before a missing second row", async () => {
  const fixture = sframePayload(3);
  fixture.view.setUint16(fixture.rowStart, 2, true);
  const table = (await parse(fixture.bytes))?.sframe?.[0];
  assert.match(table?.functions[0]?.issues.join(" ") ?? "", /Truncated frame row/);
  assert.equal(table?.rows.length, 1);
});

void test("reads 32-bit PC offsets and signed 16-bit data words", async () => {
  const fixture = sframePayload(3);
  const bytes = new Uint8Array(fixture.rowStart + 14);
  bytes.set(fixture.bytes.subarray(0, fixture.rowStart + 5));
  const view = new DataView(bytes.buffer);
  view.setUint32(16, 14, true); // Nine-byte FRE with two 16-bit words after the five-byte attributes.
  view.setUint8(fixture.rowStart + 2, 2); // FRE type ADDR4.
  view.setUint32(fixture.rowStart + 5, 0x80000000, true);
  view.setUint8(fixture.rowStart + 9, 0x25);
  view.setInt16(fixture.rowStart + 10, -32000, true);
  view.setInt16(fixture.rowStart + 12, 1000, true);
  const row = (await parse(bytes))?.sframe?.[0]?.rows[0];
  assert.equal(row?.pcOffset, 0x80000000);
  assert.deepEqual(row?.words, [-32000, 1000]);
});

void test("honors a nonzero descriptor table offset and decodes the v2 repeat size", async () => {
  const fixture = sframePayload(2);
  // v2 stores the repeat size at FDE+17 when bit 4 marks repeating PCs.
  fixture.bytes[fixture.descriptorStart + 16]! |= 0x10;
  fixture.bytes[fixture.descriptorStart + 17] = 16;
  const bytes = new Uint8Array(fixture.bytes.length + 4);
  bytes.set(fixture.bytes.subarray(0, fixture.descriptorStart));
  bytes.set(fixture.bytes.subarray(fixture.descriptorStart), fixture.descriptorStart + 4);
  const view = new DataView(bytes.buffer);
  view.setUint32(20, 4, true);
  view.setUint32(24, 24, true);
  const table = (await parse(bytes))?.sframe?.[0];
  assert.equal(table?.functions[0]?.offset, 36);
  assert.equal(table?.functions[0]?.attributes?.repeatSize, 16);
  assert.deepEqual(table?.issues, []);
});

void test("reads one-byte PC offsets and signed 32-bit data words", async () => {
  const fixture = sframePayload(3);
  fixture.view.setUint8(fixture.rowStart + 2, 0); // FRE type ADDR1.
  fixture.view.setUint8(fixture.rowStart + 5, 0xff);
  fixture.view.setUint8(fixture.rowStart + 6, 0x43); // SP with one 32-bit word.
  fixture.view.setInt32(fixture.rowStart + 7, -0x12345678, true);
  const row = (await parse(fixture.bytes))?.sframe?.[0]?.rows[0];
  assert.equal(row?.pcOffset, 255);
  assert.deepEqual(row?.words, [-0x12345678]);
});

void test("retains the maximum number of data words in a frame row", async () => {
  const fixture = sframePayload(3);
  // SFrame §2.4.1: the 4-bit word count can represent 15 words of four bytes.
  const words = Array.from({ length: 15 }, (_, index) => index - 7);
  const freBytes = 2 + words.length * 4;
  const attributeEnd = fixture.rowStart + 5;
  const bytes = new Uint8Array(attributeEnd + freBytes);
  bytes.set(fixture.bytes.subarray(0, attributeEnd));
  const view = new DataView(bytes.buffer);
  view.setUint32(16, 5 + freBytes, true);
  view.setUint8(fixture.rowStart + 2, 0); // FRE type ADDR1.
  view.setUint8(attributeEnd + 1, 0x5f); // SP, 15 words, four bytes each.
  words.forEach((word, index) => view.setInt32(attributeEnd + 2 + index * 4, word, true));
  assert.deepEqual((await parse(bytes))?.sframe?.[0]?.rows[0]?.words, words);
});

void test("bounds duplicate frame offsets without expanding the same record repeatedly", async () => {
  const payload = sframePayload(3, true, 2);
  payload.view.setUint32(payload.descriptorStart + 16 + 12, 0, true);
  const table = (await parse(payload.bytes))?.sframe?.[0];
  assert.match(table?.functions[0]?.issues.join(" ") ?? "", /Duplicate SFrame function row offset/);
  assert.deepEqual(table?.rows.map(row => row.functionIndex), [1]);
});

void test("reports compressed and out-of-file SFrame sections", async () => {
  const bytes = sframeElf(sframePayload(3).bytes, true, "object");
  const view = new DataView(bytes.buffer);
  view.setBigUint64(200, 0x800n, true); // SHF_COMPRESSED, ELF gABI §3.
  const compressed = await parseElf(new File([bytes], "compressed.o"));
  view.setBigUint64(200, 0n, true);
  view.setBigUint64(216, 0xffffffffffffffffn, true);
  const outside = await parseElf(new File([bytes], "outside.o"));
  assert.match(compressed?.sframe?.[0]?.issues[0] ?? "", /compressed/);
  assert.match(outside?.sframe?.[0]?.issues[0] ?? "", /outside the file/);
});
