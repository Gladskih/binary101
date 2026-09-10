import assert from "node:assert/strict";
import { test } from "node:test";
import { evaluateElfCfi } from "../../../../analyzers/elf/cfi-state.js";
import type { ElfUnwindCie, ElfUnwindFde } from "../../../../analyzers/elf/unwind-types.js";

const cie: ElfUnwindCie = { offset: 0, version: 1, augmentation: "", addressSize: 8,
  codeAlignment: 2n, dataAlignment: -8n, returnRegister: 16n, fdeEncoding: 0,
  lsdaEncoding: 255, personality: null, instructions: [
    { offset: 0, operation: "def_cfa", operands: [7n, 8n] },
    { offset: 1, operation: "offset", operands: [16n, 1n] }
  ] };
const fde = (operations: [string, (bigint | string)[]][]): ElfUnwindFde => ({
  offset: 64, cieOffset: 0, start: { address: 4096n, indirect: false }, range: 32n,
  lsda: null, instructions: operations.map(([operation, operands], offset) => ({ offset, operation, operands }))
});

void test("evaluates CIE defaults, alignment factors and restored FDE register rules", () => {
  const result = evaluateElfCfi(cie, fde([["advance_loc", [2n]], ["def_cfa_offset", [16n]],
    ["offset", [6n, 2n]], ["advance_loc1", [1n]], ["restore", [6n]]]));
  assert.deepEqual(result.issues, []);
  assert.deepEqual(result.rows.map(row => row.location), [4096n, 4100n, 4102n]);
  assert.deepEqual(result.rows[1]?.cfa, { register: 7n, offset: 16n });
  assert.deepEqual(result.rows[1]?.registers["6"], { kind: "offset", offset: -16n });
  assert.equal(result.rows[2]?.registers["6"], undefined);
  assert.deepEqual(result.rows[2]?.registers["16"], { kind: "offset", offset: -8n });
});

void test("remember and restore state preserve rules without rewinding the location", () => {
  const result = evaluateElfCfi(cie, fde([["remember_state", []], ["def_cfa", [6n, 16n]],
    ["advance_loc", [1n]], ["restore_state", []]]));
  assert.deepEqual(result.rows[0]?.cfa, { register: 6n, offset: 16n });
  assert.deepEqual(result.rows[1]?.cfa, { register: 7n, offset: 8n });
  assert.equal(result.rows[1]?.location, 4098n);
});

void test("reports stack underflow, unsupported operations and invalid locations", () => {
  assert.match(evaluateElfCfi(cie, fde([["restore_state", []]])).issues.join(" "), /stack/);
  assert.match(evaluateElfCfi(cie, fde([["unknown", []]])).issues.join(" "), /Unsupported/);
  assert.match(evaluateElfCfi(cie, fde([["set_loc", [4095n]]])).issues.join(" "), /location/);
  assert.match(evaluateElfCfi(cie, fde([["advance_loc", [100n]]])).issues.join(" "), /range/);
});

void test("restores CIE rules and supports every advance encoding and set_loc", () => {
  const result = evaluateElfCfi(cie, fde([["undefined", [16n]], ["advance_loc2", [1n]],
    ["restore_extended", [16n]], ["advance_loc4", [1n]], ["set_loc", [4110n]]]));
  assert.deepEqual(result.rows.map(row => row.location), [4096n, 4098n, 4100n, 4110n]);
  assert.deepEqual(result.rows[0]?.registers["16"], { kind: "undefined" });
  assert.deepEqual(result.rows[1]?.registers["16"], { kind: "offset", offset: -8n });
});

void test("rejects unresolved start, invalid CIE and malformed operands", () => {
  assert.match(evaluateElfCfi(cie, { ...fde([]), start: null }).issues.join(" "), /resolved/);
  assert.match(evaluateElfCfi(cie, { ...fde([]), start: { address: 4096n, indirect: true } })
    .issues.join(" "), /resolved/);
  assert.match(evaluateElfCfi({ ...cie, instructions: [{ offset: 0, operation: "unknown", operands: [] }] },
    fde([])).issues.join(" "), /CIE/);
  assert.match(evaluateElfCfi(cie, fde([["restore", []]])).issues.join(" "), /invalid/);
  assert.match(evaluateElfCfi(cie, fde([["set_loc", []]])).issues.join(" "), /operand/);
  assert.match(evaluateElfCfi(cie, fde([["set_loc", [4096n]]])).issues.join(" "), /advance/);
});

void test("does not add a row past the FDE end or duplicate zero advance rows", () => {
  const result = evaluateElfCfi(cie, fde([["advance_loc", [0n]], ["advance_loc", [16n]]]));
  assert.deepEqual(result.rows.map(row => row.location), [4096n]);
  assert.deepEqual(result.issues, []);
});

void test("bounds saved state depth and expanded row count", () => {
  assert.match(evaluateElfCfi(cie, fde(Array.from({ length: 4097 }, () => ["remember_state", []])))
    .issues.join(" "), /stack limit/);
  assert.match(evaluateElfCfi(cie, { ...fde(Array.from({ length: 4096 }, () => ["advance_loc", [1n]])),
    range: 10000n }).issues.join(" "), /row limit/);
});
