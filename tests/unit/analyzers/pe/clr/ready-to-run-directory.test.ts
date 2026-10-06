import assert from "node:assert/strict";
import test from "node:test";
import { readReadyToRunDirectory } from "../../../../../analyzers/pe/clr/ready-to-run-directory.js";
import { createReadyToRunCompositeFixture, createLargeReadyToRunDirectoryFixture } from
  "../../../../helpers/ready-to-run-composite-fixture.js";
import { MockFile } from "../../../../helpers/mock-file.js";

const identityRva = (rva: number): number => rva;

void test("reads a core directory without assuming a signature or version prefix", async () => {
  const fixture = createReadyToRunCompositeFixture();
  const issues: string[] = [];

  assert.deepEqual(await readReadyToRunDirectory(fixture.reader, identityRva, 0x108, 12, 1, issues),
    [{ type: 103, name: "MethodDefEntryPoints", rva: 0x180, size: 4 }]);
  assert.deepEqual(issues, []);
});

void test("retains complete rows before a physically truncated directory", async () => {
  const fixture = createReadyToRunCompositeFixture();
  const issues: string[] = [];

  assert.equal((await readReadyToRunDirectory(fixture.reader, identityRva, 0x108, 12, 2, issues)).length, 1);
  assert.deepEqual(issues, ["ReadyToRun section table is truncated."]);
});

void test("warns about duplicate types and invalid section RVA ranges", async () => {
  const fixture = createReadyToRunCompositeFixture();
  fixture.view.setUint32(0x114, 103, true);
  fixture.view.setUint32(0x118, 0xffffffff, true);
  fixture.view.setUint32(0x11c, 4, true);
  const issues: string[] = [];

  await readReadyToRunDirectory(new MockFile(fixture.bytes), identityRva, 0x108, 24, 2, issues);
  assert.match(issues.join(" "), /strictly increasing/);
  assert.match(issues.join(" "), /invalid RVA range/);
});

for (const [rva, size, count] of [[-1, 12, 1], [0, -1, 1], [0, 12, -1],
  [0, 12, 1.5], [0, 12, NaN], [0, 12, Infinity], [0, 12, 0x100000000], [0xffffffff, 12, 1]]) {
  void test(`rejects invalid directory coordinates ${rva}/${size}/${count}`, async () => {
    const fixture = createReadyToRunCompositeFixture();
    const issues: string[] = [];

    assert.deepEqual(await readReadyToRunDirectory(fixture.reader, value => value, rva!, size!, count!, issues), []);
    assert.match(issues.join(), /invalid range or count/);
  });
}

void test("accepts empty directories and preserves the available prefix of a uint32 count", async () => {
  const fixture = createReadyToRunCompositeFixture();
  const issues: string[] = [];

  assert.deepEqual(await readReadyToRunDirectory(fixture.reader, identityRva, 0, 0, 0, issues), []);
  assert.deepEqual(issues, []);
  assert.equal((await readReadyToRunDirectory(fixture.reader, identityRva, 0x108, 12, 0xffffffff, issues)).length, 1);
  assert.match(issues.join(), /truncated/);
});

void test("reads every directory entry in bounded buffers without a record cap", async context => {
  const fixture = createLargeReadyToRunDirectoryFixture();
  const reads = context.mock.method(fixture.reader, "read");
  const issues: string[] = [];

  const sections = await readReadyToRunDirectory(fixture.reader, identityRva, 0,
    fixture.reader.size, fixture.count, issues);

  assert.equal(sections.length, fixture.count);
  assert.equal(sections.at(-1)?.type, 15999);
  assert.equal(sections.at(-1)?.name, "Unknown(15999)");
  assert.deepEqual(issues, []);
  assert.ok(reads.mock.calls.every(call => call.arguments[1] <= 64 * 1024));
});

void test("retains earlier chunks when a later read fails", async context => {
  const fixture = createLargeReadyToRunDirectoryFixture();
  const read = fixture.reader.read.bind(fixture.reader);
  const issues: string[] = [];
  context.mock.method(fixture.reader, "read", async (offset: number, size: number) => {
    if (offset) throw new Error("later chunk failed");
    return read(offset, size);
  });

  assert.equal((await readReadyToRunDirectory(fixture.reader, identityRva, 0,
    fixture.reader.size, fixture.count, issues)).length, 5461);
  assert.match(issues.join(), /later chunk failed/);
  assert.match(issues.join(), /truncated/);
});

void test("reports unmapped tables and non-Error failures", async context => {
  const fixture = createReadyToRunCompositeFixture();
  const issues: string[] = [];
  context.mock.method(fixture.reader, "read", async () => { throw "failure"; });

  assert.deepEqual(await readReadyToRunDirectory(fixture.reader, () => null, 0x108, 12, 1, issues), []);
  assert.deepEqual(await readReadyToRunDirectory(fixture.reader, identityRva, 0x108, 12, 1, issues), []);
  assert.match(issues.join(), /directory read failed/);
});
