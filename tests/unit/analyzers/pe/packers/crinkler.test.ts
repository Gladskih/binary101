import assert from "node:assert/strict";
import { test } from "node:test";
import { parseForUi } from "../../../../../analyzers/index.js";
import { isPeWindowsParseResult } from "../../../../../analyzers/pe/index.js";
import { peSubtypeLabel } from "../../../../../analyzers/pe/subtype-labels.js";
import { renderHeaders } from "../../../../../renderers/pe/headers.js";
import { renderPackerReport } from "../../../../../renderers/pe/packers.js";
import {
  CRINKLER_13_PREFIX, CRINKLER_20_TINY, CRINKLER_30_PREFIX,
  CRINKLER_30_TINY, CRINKLER_TINY_UNPACKED
} from "../../../../fixtures/crinkler-bytes.js";

const parseFixture = async (value: string) => {
  const result = await parseForUi(new File([Buffer.from(value, "hex")], "probe.exe"));
  assert.equal(result.analyzer, "pe");
  assert.ok(result.parsed && isPeWindowsParseResult(result.parsed));
  const report = result.parsed.packers?.reports.find(item => item.id === "crinkler");
  return { pe: result.parsed, report, finding: report?.findings[0] };
};

void test("Crinkler Tiny Header decodes both x86 stub layouts without changing the PE headers",
  async () => {
    const legacy = await parseFixture(CRINKLER_20_TINY);
    const current = await parseFixture(CRINKLER_30_TINY);
    assert.equal(legacy.finding?.id, "crinkler");
    assert.equal(current.finding?.id, "crinkler");
    assert.equal(legacy.finding.layout.version, "2.0");
    assert.equal(current.finding.layout.version, "3.0");
    assert.equal(current.finding.layout.entryRva, 0x64);
    assert.equal(current.pe.coff.SizeOfOptionalHeader, 8);
    assert.equal(current.pe.opt.AddressOfEntryPoint, 0);
    assert.equal(current.pe.dirs.length, 0);
    assert.equal(current.pe.subtype, "crinkler");
    assert.equal(peSubtypeLabel(current.pe.subtype), "Crinkler-packed PE");
    assert.equal(legacy.finding.decoded?.packedSize, 91);
    assert.equal(current.finding.decoded?.packedSize, 91);
    // The independently disassembled import stub stores slots at 0x420100.
    assert.equal(current.finding.decoded?.imports?.tableVa, 0x420100);
    assert.equal(Buffer.from(legacy.finding.decoded?.data ?? []).toString("hex"),
      CRINKLER_TINY_UNPACKED);
    assert.equal(Buffer.from(current.finding.decoded?.data ?? []).toString("hex"),
      CRINKLER_TINY_UNPACKED);
    assert.deepEqual(current.report?.warnings, []);
    assert.equal(current.pe.overlay, undefined);
  });

void test("Crinkler reads legacy and 3.0 model records using the version's part layout",
  async () => {
    const legacy = await parseFixture(CRINKLER_13_PREFIX);
    const current = await parseFixture(CRINKLER_30_PREFIX);
    assert.equal(legacy.finding?.id, "crinkler");
    assert.equal(current.finding?.id, "crinkler");
    assert.equal(legacy.finding.layout.profile, "compatibility");
    assert.equal(legacy.finding.layout.entryOffset, 2);
    assert.deepEqual(legacy.finding.parts?.map(part => part.unpackedSize), [154, 10]);
    assert.deepEqual(current.finding.parts?.map(part => part.unpackedSize), [150, 10]);
    // 3.0b uses even parity of the low weight byte, with one model in the data record.
    assert.deepEqual(current.finding.parts?.map(part => part.models.length), [4, 1]);
    assert.deepEqual(current.report?.warnings, []);
    assert.equal(current.finding.decoded, undefined);
  });

void test("Crinkler rejects an incompatible PE alignment even with Crinkler version digits",
  async () => {
    // The compact Crinkler loader template always records FileAlignment = 4 at file offset 0x40.
    const bytes = Buffer.from(CRINKLER_30_TINY, "hex");
    bytes.writeUInt32LE(8, 0x40);
    const { pe, report } = await parseFixture(bytes.toString("hex"));
    assert.equal(pe.subtype, undefined);
    assert.equal(report, undefined);
  });

void test("Crinkler reports an incomplete stream and preserves trailing bytes after a valid stream",
  async () => {
    const truncated = await parseFixture(CRINKLER_30_TINY.slice(0, -20));
    const appended = await parseFixture(CRINKLER_30_TINY + "deadbeef");
    assert.equal(truncated.finding?.id, "crinkler");
    assert.equal(truncated.finding.decoded, undefined);
    assert.match(truncated.report?.warnings.join(" ") ?? "", /verified decode/);
    assert.deepEqual(appended.pe.overlay?.ranges.map(range => [range.start, range.end]), [[317, 321]]);
  });

void test("Crinkler keeps the subtype when the declared output exceeds the local analysis budget",
  async () => {
    const bytes = Buffer.from(CRINKLER_30_TINY, "hex");
    // header22_1k.asm stores the end position in the operand of cmp di, imm16.
    bytes.writeUInt16LE(0xffff, 0xc9);
    const { finding, report } = await parseFixture(bytes.toString("hex"));
    assert.equal(finding?.id, "crinkler");
    assert.equal(finding.decoded, undefined);
    assert.match(report?.warnings.join(" ") ?? "", /exceeds.*decode limit/);
  });

void test("Crinkler never follows a packed-data pointer beyond the end of the file", async () => {
  const bytes = Buffer.from(CRINKLER_30_TINY, "hex");
  // header22_1k.asm encodes the bitstream VA as the absolute operand of bt at 0x0c.
  bytes.writeUInt32LE(0xffffffff, 0x0f);
  const { finding, report } = await parseFixture(bytes.toString("hex"));
  assert.equal(finding?.id, "crinkler");
  assert.equal(finding.decoded, undefined);
  assert.match(report?.warnings.join(" ") ?? "", /beyond the end of the file/);
});

void test("Crinkler shows recovered data alongside the declared PE header span", async () => {
  const { pe, report } = await parseFixture(CRINKLER_30_TINY);
  const headers: string[] = [];
  const packer: string[] = [];
  renderHeaders(pe, headers);
  renderPackerReport(report, packer);
  assert.match(headers.join(""), /The declared optional header ends here/);
  assert.doesNotMatch(headers.join(""), />AddressOfEntryPoint</);
  assert.match(packer.join(""), /Decompressor entry RVA/);
  assert.match(packer.join(""), /Verified unpacked bytes/);
  assert.match(packer.join(""), /Tiny Import resolver/);
});
