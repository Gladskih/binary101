import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeCustomState } from "../../../../../analyzers/pe/debug/portable-pdb-custom-state.js";

const counts = new Map([[0x06, 2], [0x30, 2]]);
const decode = (type: string, bytes: number[]) => decodeCustomState(type, Uint8Array.from(bytes), counts);

void test("Portable PDB summarizes hoisted scopes including inactive compiler placeholders", () => {
  // uint32 pairs: (0,8), (4,8), (0,0). Their summed lengths are not unique IL coverage.
  assert.deepEqual(decode("hoistedScopes", [
    0, 0, 0, 0, 8, 0, 0, 0, 4, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
  ]), { type: "hoistedScopes", scopes: 3, inactiveScopes: 1, totalIlBytes: 16 });
  assert.throws(() => decode("hoistedScopes", [0]), /truncated/);
  assert.throws(() => decode("hoistedScopes", [1, 0, 0, 0, 0, 0, 0, 0]), /scope/);
  assert.throws(() => decode("hoistedScopes", [255, 255, 255, 127, 1, 0, 0, 0]), /scope/);
});

void test("Portable PDB counts encoded dynamic flags without inventing variable counts", () => {
  assert.deepEqual(decode("dynamicFlags", [129, 255, 0]), { type: "dynamicFlags", storedBits: 24, setBits: 10 });
  assert.deepEqual(decode("dynamicFlags", []), { type: "dynamicFlags", storedBits: 0, setBits: 0 });
});

void test("Portable PDB parses Roslyn EnC slot encodings including temporary slots", () => {
  // Roslyn: 0xff baseline marker, zero-byte temporary, high bit means ordinal follows.
  assert.deepEqual(decode("encSlots", [255, 2, 0, 1, 3, 129, 4, 1]),
    { type: "encSlots", slots: 3, temporaries: 1, ordinalSlots: 1 });
  assert.deepEqual(decode("encSlots", []), { type: "encSlots", slots: 0, temporaries: 0, ordinalSlots: 0 });
  assert.throws(() => decode("encSlots", [255]), /compressed/);
  assert.throws(() => decode("encSlots", [1]), /compressed/);
  assert.throws(() => decode("encSlots", [129, 0]), /compressed/);
});

void test("Portable PDB parses Roslyn EnC closures and special static/this lambda ordinals", () => {
  // Roslyn MinClosureOrdinal is -2: encoded 0,1 are this-only/static, 2 is closure #0.
  assert.deepEqual(decode("encLambdas", [1, 1, 1, 5, 2, 0, 3, 1, 4, 2]),
    { type: "encLambdas", closures: 1, lambdas: 3 });
  assert.deepEqual(decode("encLambdas", []), { type: "encLambdas", closures: 0, lambdas: 0 });
  assert.throws(() => decode("encLambdas", [1, 1, 0, 0, 2]), /closure/);
  assert.throws(() => decode("encLambdas", [1, 1, 127]), /count/);
  assert.throws(() => decode("encLambdas", [1, 1, 0, 0]), /compressed/);
});

void test("Portable PDB parses EnC state numbers and ordered syntax offsets", () => {
  // Count 2, baseline 0, then signed state/unsigned syntax pairs.
  assert.deepEqual(decode("encStates", [2, 0, 0, 1, 2, 1]), { type: "encStates", states: 2 });
  assert.deepEqual(decode("encStates", [0]), { type: "encStates", states: 0 });
  assert.deepEqual(decode("encStates", []), { type: "encStates", states: 0 });
  assert.throws(() => decode("encStates", [2, 0, 0, 2, 2, 1]), /ordered/);
  assert.throws(() => decode("encStates", [1, 0, 0]), /compressed/);
  assert.throws(() => decode("encStates", [0, 0]), /trailing/);
});

void test("Portable PDB bounds repeated state ordinals to Roslyn's byte-sized representation", () => {
  const bytes = Uint8Array.from([129, 1, 0, ...Array.from({ length: 257 }, () => [0, 0]).flat()]);

  assert.throws(() => decodeCustomState("encStates", bytes, counts), /ordinal/);
});

const createStateMap = (offsets: number[]): Uint8Array => {
  const encode = (value: number): number[] => value < 128 ? [value] : [0x80 | (value >> 8), value & 255];
  return Uint8Array.from([...encode(offsets.length), 0, ...offsets.flatMap(offset => [0, ...encode(offset)])]);
};

void test("Portable PDB permits 256 repeated await ordinals and resets them at distinct syntax offsets", () => {
  assert.deepEqual(decodeCustomState("encStates", createStateMap(new Array<number>(256).fill(0)), counts),
    { type: "encStates", states: 256 });
  assert.deepEqual(decodeCustomState("encStates", createStateMap(Array.from({ length: 257 }, (_, index) => index)), counts),
    { type: "encStates", states: 257 });
});

void test("Portable PDB parses async catch-handler and await/resume metadata", () => {
  assert.deepEqual(decode("asyncStepping", [1, 0, 0, 0, 4, 0, 0, 0, 8, 0, 0, 0, 2]),
    { type: "asyncStepping", hasCatchHandler: true, awaits: 1 });
  assert.deepEqual(decode("asyncStepping", [0, 0, 0, 0]),
    { type: "asyncStepping", hasCatchHandler: false, awaits: 0 });
  // CatchHandlerOffset is int32.MaxValue; the encoded uint32 stores offset + 1.
  assert.deepEqual(decode("asyncStepping", [0, 0, 0, 128]),
    { type: "asyncStepping", hasCatchHandler: true, awaits: 0 });
  assert.throws(() => decode("asyncStepping", [0, 0, 0, 0, 1]), /truncated/);
  assert.throws(() => decode("asyncStepping", [1, 0, 0, 128]), /offset/);
  assert.throws(() => decode("asyncStepping", [0, 0, 0, 0, 0, 0, 0, 128, 0, 0, 0, 0, 1]), /offset/);
  assert.throws(() => decode("asyncStepping", [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 1]), /offset/);
  assert.throws(() => decode("asyncStepping", [0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3]), /MethodDef/);
});

void test("Portable PDB decodes type document references and the primary constructor marker", () => {
  assert.deepEqual(decode("typeDocuments", [1, 2]), { type: "typeDocuments", documents: [1, 2] });
  assert.deepEqual(decode("primaryConstructor", []), { type: "primaryConstructor" });
  assert.throws(() => decode("primaryConstructor", [0]), /trailing/);
  assert.throws(() => decode("typeDocuments", [0]), /Document/);
  assert.throws(() => decode("typeDocuments", [3]), /Document/);
  assert.throws(() => decode("unknown", []), /unsupported/);
});
