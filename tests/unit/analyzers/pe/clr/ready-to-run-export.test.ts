import assert from "node:assert/strict";
import test from "node:test";
import { parseExportedReadyToRun } from "../../../../../analyzers/pe/clr/ready-to-run-export.js";
import { createReadyToRunCompositeFixture } from "../../../../helpers/ready-to-run-composite-fixture.js";

const identityRva = (rva: number): number => rva;

void test("finds composite headers through RTR_HEADER without a CLR native directory size", async () => {
  const fixture = createReadyToRunCompositeFixture();

  const parsed = await parseExportedReadyToRun(fixture.reader, identityRva,
    [{ ordinal: 1, rva: 0x20, names: ["RTR_HEADER"] }], 0x8664);

  assert.equal(parsed?.status, "ready-to-run");
  assert.equal(parsed?.sections.length, 2);
  assert.equal(parsed?.sections[1]?.decoded?.kind, "components");
});

void test("ignores unrelated exports and rejects forwarded or ambiguous headers", async () => {
  const fixture = createReadyToRunCompositeFixture();
  const entry = { ordinal: 1, rva: 0x20, names: ["RTR_HEADER"] };

  assert.equal(await parseExportedReadyToRun(fixture.reader, identityRva, []), null);
  assert.equal(await parseExportedReadyToRun(fixture.reader, identityRva,
    [{ ...entry, names: ["Main"] }]), null);
  assert.match((await parseExportedReadyToRun(fixture.reader, identityRva,
    [{ ...entry, forwarder: "module.symbol" }]))!.issues.join(), /forwarded/);
  assert.match((await parseExportedReadyToRun(fixture.reader, identityRva,
    [entry, { ...entry, ordinal: 2 }]))!.issues.join(), /ambiguous/);
});

void test("unmapped and unreadable exported headers produce visible warnings", async context => {
  const fixture = createReadyToRunCompositeFixture();
  const entries = [{ ordinal: 1, rva: 0x20, names: ["RTR_HEADER"] }];

  assert.equal((await parseExportedReadyToRun(fixture.reader, () => null, entries))?.status, "unmapped");
  context.mock.method(fixture.reader, "read", async () => { throw new Error("disk read failed"); });
  assert.match((await parseExportedReadyToRun(fixture.reader, identityRva, entries))!.issues.join(),
    /disk read failed/);
});
