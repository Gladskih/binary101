import assert from "node:assert/strict";
import { test } from "node:test";
import { readDwarfInformation } from "../../../../analyzers/dwarf/information.js";
import { createDwarfSectionFile } from "../../../fixtures/dwarf-semantic-fixture.js";
import {
  concatenateBytes, encodeDwarf32Unit, encodeUint16, encodeUint32, encodeUint64
} from "../../../fixtures/dwarf-fixture-encoding.js";

const readInformation = async (contents: Array<{ name: string; bytes: number[] }>, issues: string[]) => {
  const fixture = createDwarfSectionFile(contents);
  const sections = new Map(fixture.sections.map(section => [section.name, {
    section, summary: section, reader: fixture.file, decoded: true
  }]));
  return readDwarfInformation([sections.get(".debug_info")!], sections, "little", issues);
};
const compileUnit = (abbreviationOffset: number): number[] => encodeDwarf32Unit(concatenateBytes(
  encodeUint16(4), encodeUint32(abbreviationOffset), [8, 1]
));

void test("information parsing continues to later units after a bad abbreviation reference", async () => {
  const issues: string[] = [];

  const units = await readInformation([
    { name: ".debug_info", bytes: concatenateBytes(compileUnit(99), compileUnit(0), compileUnit(0)) },
    { name: ".debug_abbrev", bytes: [1, 0x11, 0, 0, 0, 0] }
  ], issues);

  assert.equal(units.length, 2);
  assert.equal(units[0]?.dies[0]?.tag, 0x11);
  assert.match(issues.join(" "), /abbreviation offset 99/);
});

void test("information preserves type signatures, type offsets, and split-debug identities", async () => {
  const issues: string[] = [];
  // DWARF32 v5 type header occupies 24 bytes; skeleton header occupies 20 (7.5.1).
  const units = await readInformation([
    { name: ".debug_info", bytes: concatenateBytes(
      encodeDwarf32Unit(concatenateBytes(encodeUint16(5), [2, 8], encodeUint32(0),
        encodeUint64(7), encodeUint32(24), [1])),
      encodeDwarf32Unit(concatenateBytes(encodeUint16(5), [4, 8], encodeUint32(6),
        encodeUint64(9), [1]))
    ) },
    { name: ".debug_abbrev", bytes: [1, 0x41, 0, 0, 0, 0, 1, 0x4a, 0, 0, 0, 0] }
  ], issues);

  assert.equal(units[0]?.typeSignature, 7n);
  assert.equal(units[0]?.typeOffset, 24n);
  assert.equal(units[1]?.dwoId, 9n);
  assert.deepEqual(issues, []);
});

void test("information reports missing abbreviations and rejects malformed unit prefixes", async () => {
  const missing: string[] = [];
  const truncated: string[] = [];

  assert.deepEqual(await readInformation([{ name: ".debug_info", bytes: compileUnit(0) }], missing), []);
  assert.match(missing.join(" "), /debug_abbrev.*required/);
  assert.deepEqual(await readInformation([
    { name: ".debug_info", bytes: [1] }, { name: ".debug_abbrev", bytes: [0] }
  ], truncated), []);
  assert.match(truncated.join(" "), /Truncated/);
});
