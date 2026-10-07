import assert from "node:assert/strict";
import { test } from "node:test";
import { DwarfCursor } from "../../../../analyzers/dwarf/cursor.js";
import { readDwarfFrameCie } from "../../../../analyzers/dwarf/frame-cie.js";
import { dwarfMacroSources } from "../../../fixtures/dwarf-macro-fixture.js";

const readCie = async (bytes: number[], addressSize = 4) => {
  const issues: string[] = [];
  const source = dwarfMacroSources([{ name: ".debug_frame", bytes }]).get(".debug_frame")!;
  const cursor = new DwarfCursor(source.reader, source.section, 0, bytes.length, true, issues);
  return { cie: await readDwarfFrameCie(cursor, 0, 32, "little", addressSize, 3, issues), issues };
};

void test("version-1 CIE return registers use a byte and legacy address sizes come from the binary", async () => {
  const result = await readCie([1, 0, 1, 0x7c, 0x81]);

  assert.deepEqual(result.cie?.encoding, { addressSize: 4, segmentSize: 0,
    codeAlignment: 1n, dataAlignment: -4n, returnRegister: 129n });
  assert.deepEqual(result.issues, []);
});

void test("version-3 CIE return registers use unsigned LEB128", async () => {
  const result = await readCie([3, 0, 1, 0x7c, 0x81, 1]);

  assert.equal(result.cie?.encoding?.returnRegister, 129n);
  assert.deepEqual(result.issues, []);
});

void test("zero CIE code alignment is recorded and reported", async () => {
  const result = await readCie([4, 0, 4, 0, 0, 0x7c, 8]);

  assert.equal(result.cie?.encoding?.codeAlignment, 0n);
  assert.match(result.issues.join(" "), /alignment/);
});

const truncated = [[], [4], [4, 0], [4, 0, 4], [4, 0, 4, 0], [4, 0, 4, 0, 1], [4, 0, 4, 0, 1, 0x7c]];
for (const bytes of truncated) {
  void test(`CIE header cut at byte ${bytes.length} is rejected`, async () => {
    const result = await readCie(bytes);

    assert.equal(result.cie, null);
    assert.equal(result.issues.length, 1);
  });
}

void test("legacy CIEs require the target address size", async () => {
  const result = await readCie([3, 0], 0);

  assert.equal(result.cie, null);
  assert.match(result.issues.join(" "), /address size/);
});
