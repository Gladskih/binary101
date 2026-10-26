import assert from "node:assert/strict";
import { test } from "node:test";
import { readLegacyCodeViewSymbolRecords,
  readLegacyCodeViewEmbeddedSymbol, readLegacyCodeViewSymbolStream
} from "../../../../../analyzers/pe/debug/legacy-codeview-symbol-records.js";
import { legacyReader, legacySymbol, legacyU32 } from "../../../../fixtures/pe-legacy-codeview.js";
import { codeViewTextRecord } from "../../../../fixtures/pe-codeview-type-strings.js";
import { LegacyCodeViewReader } from "../../../../../analyzers/pe/debug/legacy-codeview-reader.js";
import { codeViewEntryThis, codeViewDiscarded, codeViewDeepThis,
  codeViewSymbolChain } from "../../../../fixtures/pe-codeview-embedded-symbols.js";

void test("CodeView source offsets describe root stream records without mixing embedded child offsets", async () => {
  const first = codeViewEntryThis(legacySymbol());
  const second = codeViewDiscarded(legacySymbol());
  const bytes = [...legacyU32(1), ...first, ...second];
  const stream = await readLegacyCodeViewSymbolStream(legacyReader(bytes), 4, bytes.length);

  assert.deepEqual(stream.offsets, [4, 4 + first.length]);
  assert.equal(stream.records.length, 2);
  assert.equal(stream.records[0]?.children?.length, 1);
});

void test("CodeView symbol records preserve nested entry-this and discarded symbol identity", async () => {
  const warnings: string[] = [];
  const bytes = [...codeViewEntryThis(legacySymbol()), ...codeViewDiscarded([
    ...legacySymbol(0x110e, "removed", 14), ...codeViewEntryThis(legacySymbol())])];

  assert.deepEqual(await readLegacyCodeViewSymbolRecords(legacyReader(bytes, warnings), 0, bytes.length), [
    { type: 0xe, children: [{ type: 0x203, name: "public_name",
      data: { kind: "public", typeIndex: 0, location: { segment: 0, offset: 0 } } }] },
    { type: 0x113b, discarded: { reason: 0, fileId: 0xffffffff, line: 0 },
      children: [{ type: 0x110e, name: "removed",
        data: { kind: "public", location: { segment: 0, offset: 0 }, publicFlags: 0 } },
      { type: 0xe, children: [{ type: 0x203, name: "public_name",
        data: { kind: "public", typeIndex: 0, location: { segment: 0, offset: 0 } } }] }] }
  ]);
  assert.deepEqual(warnings, []);
});

void test("CodeView nested record corruption does not consume its parent's following symbols", async () => {
  const warnings: string[] = [];
  const bytes = [...codeViewDiscarded([...legacySymbol(), 255, 255, 0, 0]), ...legacySymbol()];

  assert.deepEqual(await readLegacyCodeViewSymbolRecords(legacyReader(bytes, warnings), 0, bytes.length), [
    { type: 0x113b, discarded: { reason: 0, fileId: 0xffffffff, line: 0 },
      children: [{ type: 0x203, name: "public_name",
        data: { kind: "public", typeIndex: 0, location: { segment: 0, offset: 0 } } }] }, { type: 0x203, name: "public_name",
        data: { kind: "public", typeIndex: 0, location: { segment: 0, offset: 0 } } }
  ]);
  assert.equal(warnings.length, 1);
  assert.match(warnings[0]!, /record length/);
});

for (const records of [[], [...legacySymbol(), ...legacySymbol()]]) {
  void test(`CodeView entry-this requires exactly one complete enclosed record: ${records.length}`, async () => {
    const warnings: string[] = [];
    const bytes = codeViewEntryThis(records);
    const parsed = await readLegacyCodeViewSymbolRecords(legacyReader(bytes, warnings), 0, bytes.length);

    assert.equal(parsed[0]!.children?.length, records.length ? 2 : 0);
    assert.deepEqual(warnings, ["CodeView entry-this must contain exactly one symbol record."]);
  });
}

void test("CodeView discarded symbols validate their mandatory header and allow an empty body", async () => {
  const warnings: string[] = [];
  const bytes = [...codeViewTextRecord(0x113b, 4, []), ...codeViewDiscarded([]), ...legacySymbol()];

  assert.deepEqual(await readLegacyCodeViewSymbolRecords(legacyReader(bytes, warnings), 0, bytes.length), [
    { type: 0x113b }, { type: 0x113b, discarded: { reason: 0, fileId: 0xffffffff, line: 0 }, children: [] },
    { type: 0x203, name: "public_name", data: { kind: "public", typeIndex: 0, location: { segment: 0, offset: 0 } } }
  ]);
  assert.equal(warnings.length, 1);
  assert.match(warnings[0]!, /bounds/);
});

void test("CodeView embedded fixed headers remain bounded at nonzero record offsets", async () => {
  const warnings: string[] = [];
  const bytes = [...legacySymbol(), ...codeViewTextRecord(0x113b, 4, []), ...legacySymbol()];

  assert.deepEqual(await readLegacyCodeViewSymbolRecords(legacyReader(bytes, warnings), 0, bytes.length), [
    { type: 0x203, name: "public_name", data: { kind: "public", typeIndex: 0, location: { segment: 0, offset: 0 } } },
    { type: 0x113b }, { type: 0x203, name: "public_name", data: { kind: "public", typeIndex: 0, location: { segment: 0, offset: 0 } } }
  ]);
  assert.deepEqual(warnings,
    ["CodeView symbol 4411: Error: CodeView embedded symbol header exceeds record bounds."]);
});

void test("CodeView nested symbols use structural bounds without recursion or a depth cap", async () => {
  const warnings: string[] = [];
  const depth = 2048;
  const bytes = codeViewDeepThis(depth);
  const chain = codeViewSymbolChain(
    (await readLegacyCodeViewSymbolRecords(legacyReader(bytes, warnings), 0, bytes.length))[0]!);

  assert.equal(chain.length, depth + 1);
  assert.ok(chain.slice(0, -1).every(record => record.children?.length === 1));
  assert.deepEqual(chain.at(-1), { type: 0x110e, name: "deep",
    data: { kind: "public", location: { segment: 0, offset: 0 }, publicFlags: 0 } });
  assert.deepEqual(warnings, []);
});

void test("CodeView symbol records retain malformed text tags and stop on invalid outer framing", async () => {
  const warnings: string[] = [];
  const bytes = [...codeViewTextRecord(0x110e, 4, []), 1, 0, 0, 0];

  assert.deepEqual(await readLegacyCodeViewSymbolRecords(legacyReader(bytes, warnings), 0, bytes.length),
    [{ type: 0x110e, data: { kind: "public" } }]);
  assert.equal(warnings.length, 2);
  assert.match(warnings[0]!, /symbol fixed fields/);
  assert.match(warnings[1]!, /record length/);
});

void test("CodeView symbol records reject unreadable, truncated or invalid declared streams visibly", async () => {
  const warnings: string[] = [];

  assert.deepEqual(await readLegacyCodeViewSymbolRecords(legacyReader([0], warnings), 0, 1), []);
  assert.deepEqual(await readLegacyCodeViewSymbolRecords(legacyReader([], warnings), -1, 1), []);
  assert.deepEqual(await readLegacyCodeViewSymbolRecords(legacyReader([], warnings), 0, 1), []);
  assert.equal(warnings.length, 3);
  assert.ok(warnings.every(warning => /bounds/.test(warning)));
});

void test("CodeView embedded symbols exclude trailing type padding and preserve nested records", async () => {
  const warnings: string[] = [];
  const bytes = [...codeViewEntryThis(legacySymbol()), 0xf2, 0xf1];

  assert.deepEqual(await readLegacyCodeViewEmbeddedSymbol(legacyReader(bytes, warnings), 0),
    [{ type: 0xe, children: [{ type: 0x203, name: "public_name",
      data: { kind: "public", typeIndex: 0, location: { segment: 0, offset: 0 } } }] }]);
  assert.deepEqual(warnings, []);
});

for (const bytes of [[], [255, 255], [1, 0, 0, 0]]) {
  void test(`CodeView embedded symbols diagnose incomplete or invalid framing: ${bytes}`, async () => {
    const warnings: string[] = [];

    assert.deepEqual(await readLegacyCodeViewEmbeddedSymbol(legacyReader(bytes, warnings), 0), []);
    assert.equal(warnings.length, 1);
    assert.match(warnings[0]!, /embedded symbol:/);
  });
}

for (const reason of [0, 1, 2]) {
  void test(`CodeView discarded reason ${reason} preserves its recorded source fields`, async () => {
    const warnings: string[] = [];
    const bytes = codeViewDiscarded([]);
    bytes.splice(4, 12, ...legacyU32(reason), ...legacyU32(7), ...legacyU32(42));

    assert.deepEqual(await readLegacyCodeViewSymbolRecords(legacyReader(bytes, warnings), 0, bytes.length),
      [{ type: 0x113b, discarded: { reason, fileId: 7, line: 42 }, children: [] }]);
    assert.deepEqual(warnings, []);
  });
}

void test("CodeView discarded records warn on unknown reasons and reserved bits without losing their symbols", async () => {
  const warnings: string[] = [];
  const bytes = codeViewDiscarded(legacySymbol());
  bytes.splice(4, 4, ...legacyU32(0x103)); // Eight reason bits followed by 24 reserved bits.
  const parsed = await readLegacyCodeViewSymbolRecords(legacyReader(bytes, warnings), 0, bytes.length);

  assert.deepEqual(parsed[0]!.discarded, { reason: 3, fileId: 0xffffffff, line: 0 });
  assert.deepEqual(parsed[0]!.children, [{ type: 0x203, name: "public_name",
    data: { kind: "public", typeIndex: 0, location: { segment: 0, offset: 0 } } }]);
  assert.deepEqual(warnings, ["CodeView discarded-symbol reserved bits are nonzero.",
    "CodeView discarded-symbol reason is unknown."]);
});

for (const [start, end] of [[NaN, 0], [0, NaN], [-1, 0], [1, 0], [0.5, 0], [0, 0.5]]) {
  void test(`CodeView symbol stream validates both bounds: ${start}/${end}`, async () => {
    const warnings: string[] = [];

    assert.deepEqual(await readLegacyCodeViewSymbolRecords(legacyReader([], warnings), start!, end!), []);
    assert.deepEqual(warnings, ["CodeView symbol stream bounds exceeded."]);
  });
}

for (const [start, end] of [[0, 1], [3, 4]]) {
void test(`CodeView symbol framing never reads a short header across stream boundary ${start}/${end}`, async () => {
  const warnings: string[] = [];
  const reader = new LegacyCodeViewReader(8, async () => {
    throw new Error("Unexpected read beyond the declared symbol stream.");
  }, warning => warnings.push(warning));

  assert.deepEqual(await readLegacyCodeViewSymbolRecords(reader, start!, end!), []);
  assert.deepEqual(warnings, ["Error: CodeView symbol header exceeds stream bounds."]);
});
}

void test("CodeView symbol streams allow empty ranges and reject oversized ranges before reading", async () => {
  const warnings: string[] = [];
  const reader = new LegacyCodeViewReader(8, async () => {
    throw new Error("Unexpected read from an empty or oversized symbol stream.");
  }, warning => warnings.push(warning));

  assert.deepEqual(await readLegacyCodeViewSymbolRecords(reader, 0, 0), []);
  assert.deepEqual(await readLegacyCodeViewSymbolRecords(reader, 8, 8), []);
  assert.deepEqual(warnings, []);
  assert.deepEqual(await readLegacyCodeViewSymbolRecords(reader, 0, 9), []);
  assert.deepEqual(warnings, ["CodeView symbol stream bounds exceeded."]);
});
