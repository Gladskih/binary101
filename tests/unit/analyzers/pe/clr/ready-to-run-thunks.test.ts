import assert from "node:assert/strict";
import test from "node:test";
import { decodeReadyToRunThunkSection } from
  "../../../../../analyzers/pe/clr/ready-to-run-thunks.js";
import { thunkSectionFixture, largeThunkSectionFixture } from
  "../../../../helpers/ready-to-run-thunk-section-fixture.js";
import { arm64ThunkCode } from "../../../../helpers/ready-to-run-arm64-thunk-fixture.js";
import { armEagerThunkCode } from "../../../../helpers/ready-to-run-arm-thunk-fixture.js";

const identityRva = (rva: number): number => rva;

void test("walks the complete range and excludes compiler padding from thunk entries", async () => {
  const fixture = thunkSectionFixture();

  const thunks = await decodeReadyToRunThunkSection(fixture.reader, identityRva,
    fixture.section, 0x8664, 0n, fixture.issues);

  assert.deepEqual(thunks.map(thunk => [thunk.rva, thunk.size, thunk.helperCellRva]),
    [[0x100, 6, 0x3000], [0x108, 6, 0x3000]]);
  assert.deepEqual(fixture.issues, []);
});

void test("skips ARM64 BRK padding and inline pointer literals", async () => {
  const bytes = new Uint8Array(44);
  bytes.set(new Uint8Array(arm64ThunkCode().buffer));
  // SectionBuilder._codePadding, dotnet/runtime v10.0.0.
  new DataView(bytes.buffer).setUint32(20, 0xd43e0000, true);
  bytes.set(new Uint8Array(arm64ThunkCode().buffer), 24);
  const fixture = thunkSectionFixture(bytes);

  const thunks = await decodeReadyToRunThunkSection(fixture.reader, identityRva,
    fixture.section, 0xaa64, 0x140000000n, fixture.issues);

  assert.deepEqual(thunks.map(thunk => thunk.rva), [0x100, 0x118]);
  assert.deepEqual(fixture.issues, []);
});

void test("preserves the valid prefix and warns without scanning through unknown bytes", async () => {
  const fixture = thunkSectionFixture(Uint8Array.from(Buffer.from("ff25fa2e000090ff25f32e0000", "hex")));

  assert.equal((await decodeReadyToRunThunkSection(fixture.reader, identityRva,
    fixture.section, 0x8664, 0n, fixture.issues)).length, 1);
  assert.match(fixture.issues.join(), /unrecognized or truncated.*0x106/);
});

void test("reports unsupported architectures and invalid or unmapped ranges", async () => {
  const fixture = thunkSectionFixture();

  assert.deepEqual(await decodeReadyToRunThunkSection(fixture.reader, identityRva,
    fixture.section, 0x6232, 0n, fixture.issues), []);
  assert.match(fixture.issues.join(), /machine/);
  assert.equal(fixture.issues.length, 1);
  assert.deepEqual(await decodeReadyToRunThunkSection(fixture.reader, () => null,
    fixture.section, 0x8664, 0n, fixture.issues), []);
  assert.match(fixture.issues.join(), /truncated/);
  assert.equal(fixture.issues.length, 2);
  assert.deepEqual(await decodeReadyToRunThunkSection(fixture.reader, identityRva,
    { ...fixture.section, rva: 0xffffffff }, 0x8664, 0n, fixture.issues), []);
  assert.match(fixture.issues.join(), /invalid RVA range/);
  assert.equal(fixture.issues.length, 3);
});

void test("I/O failures produce warnings instead of escaping the parser", async context => {
  const fixture = thunkSectionFixture();
  context.mock.method(fixture.reader, "read", async () => { throw new Error("read failed"); });

  assert.deepEqual(await decodeReadyToRunThunkSection(fixture.reader, identityRva,
    fixture.section, 0x8664, 0n, fixture.issues), []);
  assert.match(fixture.issues.join(), /read failed/);
});

void test("supports Thumb2 code and both Linux and Windows undefined-instruction padding", async () => {
  const bytes = new Uint8Array(36);
  bytes.set(new Uint8Array(armEagerThunkCode().buffer));
  const view = new DataView(bytes.buffer);
  view.setUint16(16, 0xde01, true);
  view.setUint16(18, 0xdefe, true);
  bytes.set(new Uint8Array(armEagerThunkCode(0x2fec).buffer), 20);
  const fixture = thunkSectionFixture(bytes);

  const thunks = await decodeReadyToRunThunkSection(fixture.reader, identityRva,
    fixture.section, 0x1c4, 0n, fixture.issues);

  assert.deepEqual(thunks.map(thunk => thunk.rva), [0x100, 0x114]);
  assert.deepEqual(thunks.map(thunk => thunk.helperCellRva), [0x3000, 0x3000]);
  assert.deepEqual(fixture.issues, []);
});

void test("empty ranges and non-Error failures produce bounded, visible results", async context => {
  const fixture = thunkSectionFixture();
  context.mock.method(fixture.reader, "read", async () => { throw "failure"; });

  assert.deepEqual(await decodeReadyToRunThunkSection(fixture.reader, identityRva,
    { ...fixture.section, size: 0 }, 0x8664, 0n, fixture.issues), []);
  assert.deepEqual(fixture.issues, []);
  assert.deepEqual(await decodeReadyToRunThunkSection(fixture.reader, identityRva,
    fixture.section, 0x8664, 0n, fixture.issues), []);
  assert.match(fixture.issues.join(), /range read failed/);
});

void test("bad data cells warn but do not become instruction seeds", async () => {
  const fixture = thunkSectionFixture(Uint8Array.from(Buffer.from("ff2500000080", "hex")));

  assert.equal((await decodeReadyToRunThunkSection(fixture.reader, identityRva,
    fixture.section, 0x8664, 0n, fixture.issues)).length, 1);
  assert.match(fixture.issues.join(), /data cell is invalid/);
});

void test("finite but unmapped helper cells also produce visible warnings", async () => {
  const fixture = thunkSectionFixture();

  assert.equal((await decodeReadyToRunThunkSection(fixture.reader,
    rva => rva < 0x200 ? rva : null, fixture.section, 0x8664, 0n, fixture.issues)).length, 2);
  assert.match(fixture.issues.join(), /data cell is invalid/);
});

for (const [machine, hex] of [[0xaa64, "00003ed4"], [0x1c4, "fede"]] as const) {
  void test(`accepts a range containing only one complete padding instruction on ${machine}`, async () => {
    const fixture = thunkSectionFixture(Uint8Array.from(Buffer.from(hex, "hex")));

    assert.deepEqual(await decodeReadyToRunThunkSection(fixture.reader, identityRva,
      fixture.section, machine, 0n, fixture.issues), []);
    assert.deepEqual(fixture.issues, []);
  });
  void test(`reports truncated padding without reading a complete word on ${machine}`, async () => {
    const fixture = thunkSectionFixture(Uint8Array.from(Buffer.from(hex, "hex")).slice(0, -1));

    assert.deepEqual(await decodeReadyToRunThunkSection(fixture.reader, identityRva,
      fixture.section, machine, 0n, fixture.issues), []);
    assert.match(fixture.issues.join(), /unrecognized or truncated/);
  });
}

void test("visits more than a buffer of thunks without limiting their count", async context => {
  const fixture = largeThunkSectionFixture();
  const reads = context.mock.method(fixture.reader, "read");

  const thunks = await decodeReadyToRunThunkSection(fixture.reader, identityRva,
    fixture.section, 0x8664, 0n, fixture.issues);

  assert.equal(thunks.length, fixture.count);
  assert.equal(thunks.at(-1)?.rva, 0x100 + (fixture.count - 1) * 8);
  assert.ok(reads.mock.calls.every(call => call.arguments[1] <= 64 * 1024));
  assert.deepEqual(fixture.issues, []);
});
