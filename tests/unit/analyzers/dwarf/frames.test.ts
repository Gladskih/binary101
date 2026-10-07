import assert from "node:assert/strict";
import { test } from "node:test";
import { readDwarfFrames } from "../../../../analyzers/dwarf/frames.js";
import { createDwarfFrameBytes } from "../../../fixtures/dwarf-frame-fixture.js";
import { dwarfMacroSources } from "../../../fixtures/dwarf-macro-fixture.js";
import { concatenateBytes, encodeDwarf32Unit, encodeDwarf64Unit, encodeUint32,
  encodeUint64 } from "../../../fixtures/dwarf-fixture-encoding.js";

const readFrames = async (bytes: number[], addressSize = 4) => {
  const issues: string[] = [];
  const source = dwarfMacroSources([{ name: ".debug_frame", bytes }]).get(".debug_frame")!;
  return { frames: await readDwarfFrames(source, "little", addressSize, 3, issues), issues };
};

void test("debug frames decode complete CIE headers and factored FDE instructions", async () => {
  const result = await readFrames(createDwarfFrameBytes());

  assert.deepEqual(result.issues, []);
  assert.equal(result.frames.cies.length, 1);
  assert.deepEqual(result.frames.cies[0]?.encoding, { addressSize: 4, segmentSize: 0,
    codeAlignment: 1n, dataAlignment: -4n, returnRegister: 8n });
  assert.equal(result.frames.fdes[0]?.start, 4096n);
  assert.equal(result.frames.fdes[0]?.range, 16n);
  assert.equal(result.frames.fdes[0]?.instructions[0]?.operation, "advance_loc");
});

void test("debug frames retain unknown augmentations with a visible notice", async () => {
  const result = await readFrames(encodeDwarf32Unit(concatenateBytes(encodeUint32(0xffffffff),
    [4, 88, 0, 0])));

  assert.equal(result.frames.cies[0]?.augmentation, "X");
  assert.equal(result.frames.cies[0]?.encoding, null);
  assert.match(result.issues.join(" "), /augmentation/);
});

void test("debug frames reject CIE pointers into record interiors", async () => {
  const bytes = createDwarfFrameBytes();
  bytes.splice(24, 4, ...encodeUint32(1));

  const result = await readFrames(bytes);

  assert.equal(result.frames.fdes.length, 0);
  assert.match(result.issues.join(" "), /CIE/);
});

void test("debug frames report truncated headers and operands", async () => {
  const result = await readFrames(createDwarfFrameBytes().slice(0, -3));

  assert.equal(result.frames.cies.length, 1);
  assert.match(result.issues.join(" "), /section|Truncated|truncated/);
});

void test("debug frames accept forward CIE references and DWARF64 identifiers", async () => {
  const fde = encodeDwarf64Unit(concatenateBytes(encodeUint64(32), encodeUint32(4096), encodeUint32(16), [0, 0, 0, 0]));
  const cie = encodeDwarf64Unit(concatenateBytes(encodeUint64(0xffffffffffffffffn),
    [3, 0, 1, 0x7c, 8, 0x0c, 4, 4]));

  const result = await readFrames(concatenateBytes(fde, cie));

  assert.deepEqual(result.issues, []);
  assert.equal(result.frames.cies[0]?.offset, 32);
  assert.equal(result.frames.fdes[0]?.cieOffset, 32);
});

void test("debug frames retain segment selectors and decode CFI expressions", async () => {
  const cie = encodeDwarf32Unit(concatenateBytes(encodeUint32(0xffffffff),
    [4, 0, 4, 1, 1, 0x7c, 8, 0x0f, 2, 0x74, 4, 0]));
  const fde = encodeDwarf32Unit(concatenateBytes(encodeUint32(0), [7], encodeUint32(4096), encodeUint32(16),
    [0x10, 8, 1, 0x54, 0, 0, 0]));

  const result = await readFrames(concatenateBytes(cie, fde));

  assert.deepEqual(result.issues, []);
  assert.equal(result.frames.fdes[0]?.segment, 7n);
  assert.deepEqual(result.frames.cies[0]?.instructions[0]?.operands,
    [[{ offset: 0, opcode: 0x74, operands: [4n] }]]);
  assert.deepEqual(result.frames.fdes[0]?.instructions[0]?.operands,
    [8n, [{ offset: 0, opcode: 0x54, operands: [] }]]);
});

const invalid = [
  { name: "identifier", bytes: encodeDwarf32Unit([255]), notice: /Truncated/ },
  { name: "version", bytes: encodeDwarf32Unit(concatenateBytes(encodeUint32(0xffffffff), [2])), notice: /version/ },
  { name: "augmentation", bytes: encodeDwarf32Unit(concatenateBytes(encodeUint32(0xffffffff), [4, 65])), notice: /string/ },
  { name: "address size", bytes: encodeDwarf32Unit(concatenateBytes(encodeUint32(0xffffffff), [4, 0, 0, 0])), notice: /address size/ },
  { name: "alignment", bytes: encodeDwarf32Unit(concatenateBytes(encodeUint32(0xffffffff), [4, 0, 4, 0, 0, 0x7c, 8, 0])), notice: /alignment/ },
  { name: "CFI operand", bytes: encodeDwarf32Unit(concatenateBytes(encodeUint32(0xffffffff), [4, 0, 4, 0, 1, 0x7c, 8, 0x0c])), notice: /Truncated/ },
  { name: "CFI expression", bytes: encodeDwarf32Unit(concatenateBytes(encodeUint32(0xffffffff), [4, 0, 4, 0, 1, 0x7c, 8, 0x0f, 99])), notice: /Truncated/ },
  { name: "forbidden expression", bytes: encodeDwarf32Unit(concatenateBytes(encodeUint32(0xffffffff), [4, 0, 4, 0, 1, 0x7c, 8, 0x0f, 1, 0x9c])), notice: /forbidden/ },
  { name: "CIE padding", bytes: encodeDwarf32Unit(concatenateBytes(encodeUint32(0xffffffff), [4, 0, 4, 0, 1, 0x7c, 8])), notice: /aligned/ }
];
for (const example of invalid) {
  void test(`debug frames report invalid ${example.name}`, async () => {
    const result = await readFrames(example.bytes);

    assert.match(result.issues.join(" "), example.notice);
    assert.equal(result.frames.fdes.length, 0);
  });
}

const knownCie = createDwarfFrameBytes().slice(0, 20);
const unknownCie = encodeDwarf32Unit(concatenateBytes(encodeUint32(0xffffffff), [3, 88, 0, 0]));
const fde = (fields: number[]): number[] => encodeDwarf32Unit(concatenateBytes(encodeUint32(0), fields));

void test("unknown CIE augmentations allow FDE identity and range without guessing instructions", async () => {
  const result = await readFrames(concatenateBytes(unknownCie,
    fde(concatenateBytes(encodeUint32(4096), encodeUint32(16)))));

  assert.equal(result.frames.fdes[0]?.start, 4096n);
  assert.deepEqual(result.frames.fdes[0]?.instructions, []);
  assert.equal(result.issues.length, 1);
});

void test("unknown CIE augmentations still require the binary address size for FDEs", async () => {
  const result = await readFrames(concatenateBytes(unknownCie, fde([])), 0);

  assert.equal(result.frames.fdes.length, 0);
  assert.match(result.issues.join(" "), /FDE address size/);
});

void test("FDE ranges must fit entirely inside their record", async () => {
  const result = await readFrames(concatenateBytes(knownCie, fde(encodeUint32(4096))));

  assert.equal(result.frames.fdes.length, 0);
  assert.match(result.issues.join(" "), /Truncated/);
});

void test("FDE overflow and alignment errors remain visible", async () => {
  const result = await readFrames(concatenateBytes(knownCie,
    fde(concatenateBytes(encodeUint32(0xffffffff), encodeUint32(16), [0]))));

  assert.equal(result.frames.fdes.length, 1);
  assert.match(result.issues.join(" "), /width/);
  assert.match(result.issues.join(" "), /aligned/);
});

void test("unwind state errors are surfaced during analysis", async () => {
  const result = await readFrames(concatenateBytes(knownCie,
    fde(concatenateBytes(encodeUint32(4096), encodeUint32(16), [0x0b, 0, 0, 0]))));

  assert.equal(result.frames.fdes.length, 1);
  assert.match(result.issues.join(" "), /stack underflow/);
});
