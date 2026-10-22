import assert from "node:assert/strict";
import { test } from "node:test";
import { legacyCodeViewSubsectionName, legacyCodeViewSymbolName,
  legacyCodeViewTypeName, legacyCodeViewFieldName } from "../../../../renderers/pe/legacy-codeview-kinds.js";

// LEAF_ENUM_e in Microsoft's published cvinfo.h; retain useful domain labels.
for (const [type, name] of [[0x11, "Dimensioned array"], [0x100c, "Dimensioned array"],
  [0x1508, "Dimensioned array"], [0x13, "Precompiled type file"], [0x100e, "Precompiled type file"],
  [0x1509, "Precompiled type file"], [0x16, "Type server PDB path"], [0x1501, "Type server PDB path"],
  [0x1515, "Type server PDB path"], [0x202, "Default argument"], [0x1202, "Default argument"],
  [0x150b, "Default argument"], [0x1516, "Strided array"], [0x151b, "Vector"], [0x151c, "Matrix"],
  [0x151d, "Virtual table"], [0x1601, "Function ID"], [0x1602, "Member function ID"], [0x1605, "String ID"]] as const) {
  void test(`CodeView string-bearing leaf ${type} has the published category`, () => {
    assert.equal(legacyCodeViewTypeName(type), name);
  });
}

void test("CodeView record categories use published meanings and explicit unknown labels", () => {
  assert.equal(legacyCodeViewSubsectionName(0x120), "Modules");
  assert.equal(legacyCodeViewSubsectionName(0x12e), "Segment names");
  assert.equal(legacyCodeViewSubsectionName(0x999), "Unknown subsection 0x999");
  assert.equal(legacyCodeViewSymbolName(1), "Compiler");
  assert.equal(legacyCodeViewSymbolName(0x103), "Public symbol");
  assert.equal(legacyCodeViewSymbolName(0x203), "Public symbol");
  assert.equal(legacyCodeViewSymbolName(0x1009), "Public symbol");
  assert.equal(legacyCodeViewSymbolName(0x110e), "Public symbol");
  assert.equal(legacyCodeViewSymbolName(0xffff), "Symbol record 0xffff");
  assert.equal(legacyCodeViewTypeName(0x204), "Fields");
  assert.equal(legacyCodeViewTypeName(0xffff), "Type record 0xffff");
  assert.equal(legacyCodeViewFieldName(0x406), "Data member");
  assert.equal(legacyCodeViewFieldName(0x1502), "Enumerator");
  assert.equal(legacyCodeViewFieldName(0x151a), "Base interface");
  assert.equal(legacyCodeViewFieldName(0xffff), "Field record 0xffff");
});
