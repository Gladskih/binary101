import assert from "node:assert/strict";
import { test } from "node:test";
import { parseNtRiscExceptionTable } from "../../../../../analyzers/pe/exception/nt-risc.js";
import { riscExceptionRows, riscExceptionImage, riscExceptionMap } from "../../../../fixtures/pe-risc-exception.js";
import { MockFile } from "../../../../helpers/mock-file.js";

for (const format of ["nt-risc32", "nt-risc64"] as const) {
  void test(`${format} converts full-width VAs and summarizes inline descriptions`, async () => {
    const base = format === "nt-risc64" ? 0x1234567800000000n : 0x400000n;
    const source = riscExceptionRows([
      [base + 0x1000n, base + 0x1040n, base + 0x1100n, base + 0x1110n, base + 0x1010n],
      [base + 0x1040n, base + 0x1080n, 0n, 0n, base + 0x1040n]
    ], format === "nt-risc64" ? 8 : 4);
    const parsed = await parseNtRiscExceptionTable(riscExceptionImage(), source, source.size,
      riscExceptionMap, format, base);

    assert.equal(parsed.format, format);
    assert.equal(parsed.functionCount, 2);
    assert.deepEqual(parsed.beginRvas, [0x1000, 0x1040]);
    assert.deepEqual(parsed.rangeLengths, [64, 64]);
    assert.deepEqual(parsed.handlerRvas, [0x1100]);
    assert.equal(parsed.handlerUnwindInfoCount, 1);
    assert.equal(parsed.uniqueUnwindInfoCount, 2);
    assert.equal(parsed.invalidEntryCount, 0);
    assert.deepEqual(parsed.riscPrologs, { count: 2, empty: 1, minimumBytes: 0, maximumBytes: 16 });
    assert.deepEqual(parsed.issues, []);
  });
}

void test("NT RISC preserves valid neighbors when VAs or function ranges are malformed", async () => {
  const source = riscExceptionRows([
    [0x3fffffn, 0x401040n, 0n, 0n, 0n], [0x401000n, 0x401000n, 0n, 0n, 0n],
    [0x401000n, 0x401300n, 0n, 0n, 0n], [0x401040n, 0x401080n, 0n, 0n, 0x401040n]
  ]);
  const parsed = await parseNtRiscExceptionTable(riscExceptionImage(), source, source.size,
    riscExceptionMap, "nt-risc32", 0x400000n);

  assert.equal(parsed.functionCount, 4);
  assert.equal(parsed.invalidEntryCount, 3);
  assert.deepEqual(parsed.beginRvas, [0x1040]);
  assert.deepEqual(parsed.rangeLengths, [64]);
});

void test("NT RISC diagnoses inaccessible handler fields and unresolved prolog locations separately", async () => {
  const source = riscExceptionRows([[0x401040n, 0x401080n, 0x401300n, 0x3fffffn, 0x401050n],
    [0x401000n, 0x401040n, 0x401100n, 0n, 0x401010n],
    [0x401080n, 0x4010c0n, 1n, 1n, 0x401100n]]);
  const parsed = await parseNtRiscExceptionTable(riscExceptionImage(), source, source.size,
    riscExceptionMap, "nt-risc32", 0x400000n);

  assert.equal(parsed.invalidEntryCount, 0);
  assert.equal(parsed.handlerUnwindInfoCount, 2);
  assert.deepEqual(parsed.handlerRvas, [0x1100]);
  assert.ok(parsed.issues.includes("NT RISC exception handler VA could not be mapped."));
  assert.ok(parsed.issues.includes("NT RISC handler data VA could not be mapped."));
  assert.match(parsed.issues.join(" | "), /prolog.*outside/i);
  assert.match(parsed.issues.join(" | "), /not sorted/);
  assert.deepEqual(parsed.riscPrologs, { count: 2, empty: 0, minimumBytes: 16, maximumBytes: 16 });
});

void test("NT RISC rejects unsafe sizes and missing image bases before reading", async () => {
  const file = riscExceptionImage();
  const source = riscExceptionRows([[0x401000n, 0x401040n, 0n, 0n, 0x401010n]]);
  const missing = await parseNtRiscExceptionTable(file, source, source.size, riscExceptionMap, "nt-risc32");
  const empty = await parseNtRiscExceptionTable(file, source, 0, riscExceptionMap, "nt-risc32", 0x400000n);
  const fractional = await parseNtRiscExceptionTable(file, source, 20.5, riscExceptionMap, "nt-risc32", 0x400000n);

  assert.equal(missing.functionCount, 0);
  assert.match(missing.issues[0]!, /ImageBase/);
  assert.equal(empty.functionCount, 0);
  assert.match(empty.issues[0]!, /size/);
  assert.equal(fractional.functionCount, 0);
  assert.match(fractional.issues[0]!, /size/);
});

void test("NT RISC bounds partial and truncated copies by complete physical rows", async () => {
  const source = riscExceptionRows([[0x401000n, 0x401040n, 0n, 0n, 0x401010n]]);
  const truncated = await parseNtRiscExceptionTable(riscExceptionImage(), source, 40,
    riscExceptionMap, "nt-risc32", 0x400000n);
  const trailing = await parseNtRiscExceptionTable(riscExceptionImage(), source, 21,
    riscExceptionMap, "nt-risc32", 0x400000n);
  const short = await parseNtRiscExceptionTable(riscExceptionImage(), new MockFile(new Uint8Array(19)), 20,
    riscExceptionMap, "nt-risc32", 0x400000n);

  assert.equal(truncated.functionCount, 1);
  assert.match(truncated.issues.join(" | "), /truncated/);
  assert.equal(trailing.functionCount, 1);
  assert.match(trailing.issues.join(" | "), /multiple/);
  assert.equal(short.functionCount, 0);
  assert.match(short.issues.join(" | "), /truncated/);
});

void test("Alpha64 VA subtraction rejects offsets beyond the PE RVA space without rounding", async () => {
  const base = 0x1234567800000000n;
  const source = riscExceptionRows([[base + 0x100001000n, base + 0x100001040n, 0n, 0n, 0n]], 8);
  const parsed = await parseNtRiscExceptionTable(riscExceptionImage(), source, source.size,
    riscExceptionMap, "nt-risc64", base);

  assert.equal(parsed.invalidEntryCount, 1);
  assert.deepEqual(parsed.beginRvas, []);
});

void test("NT RISC decodes documented exception modes and retains unresolved metadata warnings", async () => {
  const source = riscExceptionRows([[0x401000n, 0x401040n, 0x401101n, 0n, 0x401013n],
    [0x401040n, 0x401080n, 1n, 0n, 0x401000n],
    [0x401080n, 0x4010c0n, 0x401100n, 0x401110n, 0x401090n]]);
  const parsed = await parseNtRiscExceptionTable(riscExceptionImage(), source, source.size,
    riscExceptionMap, "nt-risc32", 0x400000n);

  assert.deepEqual(parsed.handlerRvas, [0x1100]);
  assert.equal(parsed.handlerUnwindInfoCount, 2);
  assert.equal(parsed.invalidEntryCount, 0);
  assert.deepEqual(parsed.riscPrologs, { count: 2, empty: 0, minimumBytes: 16, maximumBytes: 16 });
  assert.deepEqual(parsed.issues, [
    "NT RISC prolog location is outside its function; indirect prolog metadata is not decoded."]);
});

void test("NT RISC combines the handler mode bit with both prolog mode bits", async () => {
  const source = riscExceptionRows(Array.from({ length: 8 }, (_, mode) => {
    const begin = 0x401000n + BigInt(mode * 16);
    return [begin, begin + 16n, BigInt(mode >> 2), 0n, begin + 4n + BigInt(mode & 3)];
  }));
  const parsed = await parseNtRiscExceptionTable(riscExceptionImage(), source, source.size,
    riscExceptionMap, "nt-risc32", 0x400000n);
  assert.deepEqual(parsed.riscExceptionModes, [1, 1, 1, 1, 1, 1, 1, 1]);
  assert.equal(parsed.handlerUnwindInfoCount, 0);
  assert.deepEqual(parsed.issues, []);
});

void test("Unknown handler tag bit 1 remains diagnostic independently of the known mode bit", async () => {
  const source = riscExceptionRows([[0x401000n, 0x401040n, 0x401102n, 0n, 0x401010n]]);
  const parsed = await parseNtRiscExceptionTable(riscExceptionImage(), source, source.size,
    riscExceptionMap, "nt-risc32", 0x400000n);
  assert.deepEqual(parsed.issues, ["Unknown NT RISC handler address tag bit 1 is set."]);
  assert.deepEqual(parsed.riscExceptionModes, [1, 0, 0, 0, 0, 0, 0, 0]);
});

void test("Alpha secondary ranges retain their own handlers and resolve a later primary procedure", async () => {
  const source = riscExceptionRows([[0x401080n, 0x4010c0n, 0x401100n, 0x401110n, 0x401000n],
    [0x401000n, 0x401040n, 0n, 0n, 0x401011n]]);
  const parsed = await parseNtRiscExceptionTable(riscExceptionImage(), source, source.size,
    riscExceptionMap, "nt-risc32", 0x400000n, 0x184);
  assert.deepEqual(parsed.alphaPrologs, { resolvedSecondaryRanges: 1, unresolvedSecondaryRanges: 0 });
  assert.deepEqual(parsed.handlerRvas, [0x1100]);
  assert.equal(parsed.riscPrologs?.count, 1);
  assert.equal(parsed.riscPrologs?.maximumBytes, 16);
  assert.deepEqual(parsed.riscExceptionModes, [1, 1, 0, 0, 0, 0, 0, 0]);
  assert.deepEqual(parsed.issues, ["NT RISC .pdata entries are not sorted by function start VA."]);
});

void test("Alpha references to absent primary procedures remain explicit", async () => {
  const source = riscExceptionRows([[0x401000n, 0x401040n, 0x401100n, 3n, 0x401100n]]);
  const parsed = await parseNtRiscExceptionTable(riscExceptionImage(), source, source.size,
    riscExceptionMap, "nt-risc32", 0x400000n, 0x184);
  assert.deepEqual(parsed.alphaPrologs, { resolvedSecondaryRanges: 0, unresolvedSecondaryRanges: 1 });
  assert.deepEqual(parsed.issues, [
    "Alpha secondary ranges do not match known procedure-start references; other secondary ABIs are not decoded."
  ]);
  assert.deepEqual(parsed.handlerRvas, []);
  assert.equal(parsed.handlerUnwindInfoCount, 0);
  assert.equal(parsed.riscPrologs, undefined);
});

void test("Alpha primary handlers remain counted independently of secondary handler metadata", async () => {
  const source = riscExceptionRows([[0x401000n, 0x401040n, 0x401101n, 0x401110n, 0x401010n],
    [0x401040n, 0x401080n, 0n, 0n, 0x401000n]]);
  const parsed = await parseNtRiscExceptionTable(riscExceptionImage(), source, source.size,
    riscExceptionMap, "nt-risc32", 0x400000n, 0x184);
  assert.equal(parsed.handlerUnwindInfoCount, 1);
  assert.deepEqual(parsed.handlerRvas, [0x1100]);
  assert.deepEqual(parsed.riscExceptionModes, [1, 0, 0, 0, 1, 0, 0, 0]);
  assert.deepEqual(parsed.issues, []);
});

for (const [handler, prolog] of [[1n, 0x401010n], [0n, 0x401011n]] as const) {
  void test(`Alpha64 tagged metadata ${handler}/${prolog} keeps an explicit unsupported warning`, async () => {
    const source = riscExceptionRows([[0x401000n, 0x401040n, handler, 0n, prolog]], 8);
    const parsed = await parseNtRiscExceptionTable(riscExceptionImage(), source, source.size,
      riscExceptionMap, "nt-risc64", 0x400000n);
    assert.equal(parsed.riscExceptionModes, undefined);
    assert.deepEqual(parsed.issues, ["Tagged Alpha64 exception metadata is not decoded."]);
  });
}

for (const base of [-1n, 0x10000000000000000n]) {
  void test(`NT RISC rejects an ImageBase outside the unsigned 64-bit domain: ${base}`, async () => {
    const parsed = await parseNtRiscExceptionTable(riscExceptionImage(), riscExceptionRows([]), 20,
      riscExceptionMap, "nt-risc32", base);

    assert.equal(parsed.functionCount, 0);
    assert.match(parsed.issues[0]!, /ImageBase/);
  });
}

void test("NT RISC validates end VAs independently of valid begin VAs", async () => {
  const source = riscExceptionRows([[0x401000n, 0x3fffffn, 0n, 0n, 0n]]);
  const parsed = await parseNtRiscExceptionTable(riscExceptionImage(), source, source.size,
    riscExceptionMap, "nt-risc32", 0x400000n);

  assert.equal(parsed.invalidEntryCount, 1);
  assert.equal(parsed.riscPrologs, undefined);
});

void test("unresolved secondary NT RISC metadata is excluded from handler and data-pointer statistics", async () => {
  // dumpbin /pdata prints HandlerData low bits as the secondary type, not a VA.
  const source = riscExceptionRows([[0x401000n, 0x401040n, 0x401100n, 3n, 0x401100n]]);
  const parsed = await parseNtRiscExceptionTable(riscExceptionImage(), source, source.size,
    riscExceptionMap, "nt-risc32", 0x400000n);

  assert.equal(parsed.invalidEntryCount, 0);
  assert.equal(parsed.handlerUnwindInfoCount, 0);
  assert.deepEqual(parsed.handlerRvas, []);
  assert.equal(parsed.riscPrologs, undefined);
  assert.deepEqual(parsed.issues,
    ["NT RISC prolog location is outside its function; indirect prolog metadata is not decoded."]);
});

void test("NT RISC supports zero image bases and a prolog ending exactly at the function end", async () => {
  const source = riscExceptionRows([[0x1000n, 0x1040n, 0n, 0n, 0x1040n],
    [0x1000n, 0x1040n, 0n, 0n, 0x1040n]]);
  const parsed = await parseNtRiscExceptionTable(riscExceptionImage(), source, source.size,
    riscExceptionMap, "nt-risc32", 0n);

  assert.equal(parsed.functionCount, 2);
  assert.equal(parsed.invalidEntryCount, 0);
  assert.deepEqual(parsed.riscPrologs, { count: 2, empty: 0, minimumBytes: 64, maximumBytes: 64 });
  assert.deepEqual(parsed.issues, []);
});

void test("Alpha64 checks full-width end VAs before accepting the last four PE RVA bytes", async () => {
  const source = riscExceptionRows([[0xfffffffcn, 0x100000000n, 0n, 0n, 0xfffffffcn]], 8);
  const parsed = await parseNtRiscExceptionTable(new MockFile(new Uint8Array(4)), source, source.size,
    rva => rva >= 0xfffffffc && rva <= 0xffffffff ? rva - 0xfffffffc : null, "nt-risc64", 0n);

  assert.equal(parsed.functionCount, 1);
  assert.equal(parsed.invalidEntryCount, 1);
  assert.deepEqual(parsed.beginRvas, []);
});

void test("Alpha64 accepts the maximum ImageBase as an integer but still validates each function VA", async () => {
  const source = riscExceptionRows([[0n, 0n, 0n, 0n, 0n]], 8);
  const parsed = await parseNtRiscExceptionTable(riscExceptionImage(), source, source.size,
    riscExceptionMap, "nt-risc64", 0xffffffffffffffffn);

  assert.equal(parsed.functionCount, 1);
  assert.equal(parsed.invalidEntryCount, 1);
  assert.deepEqual(parsed.issues, []);
});

void test("NT RISC rejects undersized complete copies before reading a partial row", async () => {
  const parsed = await parseNtRiscExceptionTable(riscExceptionImage(), riscExceptionRows([]), 4,
    riscExceptionMap, "nt-risc32", 0n);

  assert.equal(parsed.rangeLengths, undefined);
  assert.match(parsed.issues[0]!, /smaller than one entry/);
});

void test("Alpha64 accepts an address at the maximum 32-bit RVA without rounding it", async () => {
  const file = riscExceptionImage();
  const source = riscExceptionRows([[0x1000n, 0x1040n, 0x1100n, 0xffffffffn, 0x1010n]], 8);
  const parsed = await parseNtRiscExceptionTable(file, source, source.size,
    rva => rva === 0xffffffff ? file.size - 1 : riscExceptionMap(rva), "nt-risc64", 0n);

  assert.equal(parsed.invalidEntryCount, 0);
  assert.deepEqual(parsed.handlerRvas, [0x1100]);
  assert.deepEqual(parsed.issues, []);
});

void test("NT RISC handler data may point to mapped image headers at RVA zero", async () => {
  const source = riscExceptionRows([[0x401000n, 0x401040n, 0n, 0x400000n, 0x401010n]]);
  const parsed = await parseNtRiscExceptionTable(riscExceptionImage(), source, source.size,
    rva => rva === 0 ? 0 : riscExceptionMap(rva), "nt-risc32", 0x400000n);

  assert.equal(parsed.invalidEntryCount, 0);
  assert.deepEqual(parsed.issues, []);
});
