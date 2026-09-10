import assert from "node:assert/strict";
import { test } from "node:test";
import { renderElfCfiState } from "../../../../renderers/elf/cfi-state.js";
import type { ElfUnwindCie, ElfUnwindFde } from "../../../../analyzers/elf/unwind-types.js";

const cie: ElfUnwindCie = { offset: 0, version: 1, augmentation: "", addressSize: 8,
  codeAlignment: 1n, dataAlignment: -8n, returnRegister: 16n, fdeEncoding: 0,
  lsdaEncoding: 255, personality: null, instructions: [] };
const fde: ElfUnwindFde = { offset: 32, cieOffset: 0, start: { address: 4096n, indirect: false },
  range: 10n, lsda: null, instructions: [] };

void test("renders unresolved and unsupported CFI warnings", () => {
  assert.match(renderElfCfiState(cie, { ...fde, start: null }), /resolved/);
  assert.match(renderElfCfiState(cie, { ...fde,
    instructions: [{ offset: 0, operation: "<unknown>", operands: [] }] }), /&lt;unknown>/);
  assert.match(renderElfCfiState(cie, fde), /Unspecified/);
});

void test("renders all rule kinds and escapes expression bytes", () => {
  const operations: [string, (bigint | string)[]][] = [["def_cfa_expression", ["<expr>"]],
    ["offset", [1n, 2n]], ["val_expression", [2n, "<expr>"]], ["register", [3n, 4n]],
    ["undefined", [5n]], ["AARCH64_negate_ra_state", []]];
  const html = renderElfCfiState(cie, { ...fde,
    instructions: operations.map(([operation, operands], offset) => ({ offset, operation, operands })) });
  assert.match(html, /&lt;expr>/);
  assert.match(html, /CFA \+ \(-16\)/);
  assert.match(html, /r3: r4/);
  assert.match(html, /undefined/);
  assert.match(html, /Signed/);
  assert.match(renderElfCfiState(cie, { ...fde,
    instructions: [{ offset: 0, operation: "def_cfa", operands: [7n, 8n] }] }), /r7 \+ \(8\)/);
});
