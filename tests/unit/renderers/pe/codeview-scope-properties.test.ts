import assert from "node:assert/strict";
import { test } from "node:test";
import { codeViewScopeName, codeViewScopeProperties } from "../../../../renderers/pe/codeview-scope-properties.js";

void test("Inline properties summarize operation and declared-length counts without fabricating source lines", () => {
  const record = { type: 0x115d, scope: { kind: "inline" as const, inlinee: 4097, invocations: 12,
    annotations: [{ opcode: 4, operands: [8] }, { opcode: 12, operands: [16, 2] }, { opcode: 5, operands: [7] }] } };

  assert.equal(codeViewScopeName(record), "inlinee #4097");
  assert.match(codeViewScopeProperties(record), /12 invocations/);
  assert.match(codeViewScopeProperties(record), /3 annotations/);
  assert.match(codeViewScopeProperties(record), /24 declared code bytes/);
  assert.match(codeViewScopeProperties(record), /1 file change/);
});

void test("Thunk and WITH context names keep meaningful symbols and expressions", () => {
  const thunk = { type: 0x1102, name: "adjust", scope: { kind: "thunk" as const,
    ordinal: 1, adjustment: -8, target: "callee" } };

  assert.equal(codeViewScopeName(thunk), "thunk: adjust");
  assert.match(codeViewScopeProperties(thunk), /adjustor; this adjustment -8; target callee/);
  assert.equal(codeViewScopeName({ type: 0x1104, name: "object.member", scope: { kind: "with" } }), "with: object.member");
  assert.equal(codeViewScopeName(), "procedure scope");
});

void test("Scope properties keep unavailable fields and unknown ordinals explicit", () => {
  assert.equal(codeViewScopeProperties({ type: 0 }), "scope fields unavailable");
  assert.equal(codeViewScopeName({ type: 0x114d, scope: { kind: "inline" } }), "inlinee unavailable");
  assert.equal(codeViewScopeProperties({ type: 0x114d, scope: { kind: "inline" } }), "annotations unavailable");
  assert.equal(codeViewScopeProperties({ type: 0x1102, scope: { kind: "thunk" } }), "unknown thunk ordinal unavailable");
  assert.equal(codeViewScopeProperties({ type: 0x1102, scope: { kind: "thunk", ordinal: 9 } }), "unknown thunk ordinal 9");
  assert.equal(codeViewScopeProperties({ type: 0x1102, scope: { kind: "thunk", ordinal: 2, virtualEntry: -2 } }),
    "virtual call; virtual table entry -2");
  assert.equal(codeViewScopeName({ type: 0x107, scope: { kind: "block" } }), "block: (name unavailable)");
  assert.equal(codeViewScopeProperties({ type: 0x107, scope: { kind: "block" } }), "lexical block");
  assert.equal(codeViewScopeProperties({ type: 0x1104, scope: { kind: "with" } }), "WITH expression");
});

void test("Chunk changes and combined annotations contribute only their stored statistics", () => {
  assert.match(codeViewScopeProperties({ type: 0x114d, scope: { kind: "inline", annotations: [
    { opcode: 2, operands: [1] }, { opcode: 12, operands: [4, 7] }, { opcode: 6, operands: [-1] }] } }),
  /3 annotations; 4 declared code bytes \(sum\); 0 file changes; 1 chunk changes/);
});
