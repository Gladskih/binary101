import assert from "node:assert/strict";
import { test } from "node:test";
import { td32SymbolKind, td32SymbolName, td32SymbolPlacement, td32SymbolProperties } from
  "../../../../renderers/pe/td32-symbol-properties.js";

void test("TD32 names and kinds remain explicit for absent, unnamed and invalid references", () => {
  assert.equal(td32SymbolName(["name"], 1), "name");
  assert.equal(td32SymbolName([], undefined), "(name not stored)");
  assert.equal(td32SymbolName([], 0), "(unnamed)");
  assert.equal(td32SymbolName([], 4), "(unresolved name #4)");
  assert.equal(td32SymbolKind(0x20), "Procedure reference");
  assert.equal(td32SymbolKind(0x7777), "Unrecognized symbol kind 30583");
});

void test("TD32 placements preserve signed frame offsets and unsigned segmented addresses", () => {
  assert.equal(td32SymbolPlacement({ location: { offset: 0xffffffff, segment: 3 } }), "segment 3, stored offset 4294967295");
  assert.equal(td32SymbolPlacement({ frameOffset: -8 }), "stored BP-relative offset -8 (frame base unresolved)");
  assert.equal(td32SymbolPlacement({ register: 17 }), "register #17");
  assert.equal(td32SymbolPlacement({}), "not stored");
});

void test("TD32 UDT properties use only JCL's documented tag and nesting bits", () => {
  assert.equal(td32SymbolProperties({ type: 4, metadata: { flags: 7 } }, []),
    "tag declaration; nested type; unknown properties 0x4");
  assert.equal(td32SymbolProperties({ type: 4, metadata: { flags: 0 } }, []), "none");
  assert.equal(td32SymbolProperties({ type: 0x202, metadata: { flags: 7 } }, []), "producer flags 0x7");
});

void test("TD32 thunk and namespace properties preserve target names and avoid invented values", () => {
  assert.equal(td32SymbolProperties({ type: 0x206, metadata: { ordinal: 1, adjustment: -8, targetNameIndex: 1 } }, ["callee"]),
    "adjustor; this adjustment -8; target callee");
  assert.equal(td32SymbolProperties({ type: 0x206, metadata: { ordinal: 9 } }, []), "unknown thunk ordinal 9");
  assert.equal(td32SymbolProperties({ type: 0x25, metadata: { usingCount: 0 } }, []), "0 declared using entries");
  assert.equal(td32SymbolProperties({ type: 0x27, metadata: { value: "-1" } }, []), "value -1");
  assert.equal(td32SymbolProperties({ type: 3, metadata: {} }, []), "numeric value layout unresolved");
});
