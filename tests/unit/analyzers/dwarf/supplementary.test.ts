import assert from "node:assert/strict";
import { test } from "node:test";
import { readDwarfAlternateFile, readDwarfSupplementaryFile } from "../../../../analyzers/dwarf/supplementary.js";
import { dwarfMacroSources } from "../../../fixtures/dwarf-macro-fixture.js";
import { concatenateBytes, encodeCString, encodeUint16, encodeUleb } from "../../../fixtures/dwarf-fixture-encoding.js";

const supplementary = async (bytes: number[], byteOrder: "little" | "big" = "little") => {
  const sections = dwarfMacroSources([{ name: ".debug_sup", bytes }]);
  const issues: string[] = [];
  return { parsed: await readDwarfSupplementaryFile(sections.get(".debug_sup")!, byteOrder, issues), issues };
};
const alternate = async (bytes: number[]) => {
  const sections = dwarfMacroSources([{ name: ".gnu_debugaltlink", bytes }]);
  const issues: string[] = [];
  return { parsed: await readDwarfAlternateFile(sections.get(".gnu_debugaltlink")!, issues), issues };
};

void test("supplementary links preserve the complete filename and variable-size checksum", async () => {
  const result = await supplementary(concatenateBytes(encodeUint16(5), [0], encodeCString("shared.debug"),
    encodeUleb(130), new Array<number>(130).fill(7)));
  assert.deepEqual(result.parsed, { version: 5, isSupplementary: false, filename: "shared.debug",
    checksum: new Uint8Array(130).fill(7) });
  assert.deepEqual(result.issues, []);
});

void test("supplementary objects support empty filenames, absent checksums and big endian", async () => {
  const result = await supplementary([0, 5, 1, 0, 0], "big");
  assert.deepEqual(result.parsed, { version: 5, isSupplementary: true, filename: "", checksum: new Uint8Array() });
  assert.deepEqual(result.issues, []);
});

void test("supplementary headers reject invalid versions, flags and truncation", async () => {
  const version = await supplementary([4, 0, 0]);
  const flag = await supplementary([5, 0, 2]);
  const truncated = await supplementary([5]);
  assert.equal(version.parsed, null);
  assert.equal(flag.parsed, null);
  assert.equal(truncated.parsed, null);
  assert.match(version.issues.join(" "), /version or flag/);
  assert.match(flag.issues.join(" "), /version or flag/);
  assert.match(truncated.issues.join(" "), /Truncated/);
});

void test("supplementary parsing bounds filenames, checksum lengths and checksum bytes", async () => {
  const filename = await supplementary([5, 0, 0, 65]);
  const length = await supplementary([5, 0, 0, 0]);
  const checksum = await supplementary([5, 0, 0, 0, 2, 7]);
  assert.equal(filename.parsed, null);
  assert.equal(length.parsed, null);
  assert.equal(checksum.parsed, null);
  assert.match(filename.issues.join(" "), /string/);
  assert.match(length.issues.join(" "), /Truncated/);
  assert.match(checksum.issues.join(" "), /Truncated/);
});

void test("supplementary filename conventions and trailing bytes produce visible notices", async () => {
  const supplementaryName = await supplementary([5, 0, 1, 65, 0, 0]);
  const mainName = await supplementary([5, 0, 0, 0, 0, 7]);
  assert.match(supplementaryName.issues.join(" "), /must have an empty filename/);
  assert.match(mainName.issues.join(" "), /empty supplementary filename/);
  assert.match(mainName.issues.join(" "), /Trailing/);
});

void test("GNU alternate links preserve unaligned build ids without interpreting them as CRCs", async () => {
  const result = await alternate([65, 0, 7, 8, 9]);
  assert.deepEqual(result.parsed, { filename: "A", buildId: Uint8Array.of(7, 8, 9) });
  assert.deepEqual(result.issues, []);
});

void test("GNU alternate links report unterminated names and missing filenames or build ids", async () => {
  const unterminated = await alternate([65]);
  const noName = await alternate([0, 7]);
  const noId = await alternate([65, 0]);
  assert.equal(unterminated.parsed, null);
  assert.match(unterminated.issues.join(" "), /string/);
  assert.match(noName.issues.join(" "), /no filename or build identifier/);
  assert.match(noId.issues.join(" "), /no filename or build identifier/);
});

void test("GNU alternate links reject a short checksum read after a complete filename", async () => {
  const source = dwarfMacroSources([{ name: ".gnu_debugaltlink", bytes: [65, 0, 7] }]).get(".gnu_debugaltlink")!;
  const issues: string[] = [];
  const parsed = await readDwarfAlternateFile({ ...source, reader: { size: source.reader.size,
    read: (offset, size) => offset < 2 ? source.reader.read(offset, size)
      : Promise.resolve(new DataView(new ArrayBuffer(0))),
    readBytes: (offset, size) => source.reader.readBytes(offset, size) } }, issues);
  assert.equal(parsed, null);
  assert.match(issues.join(" "), /File ended/);
});
