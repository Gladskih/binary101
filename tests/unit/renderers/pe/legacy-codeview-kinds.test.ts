import assert from "node:assert/strict";
import { test } from "node:test";
import { legacyCodeViewSubsectionName, legacyCodeViewSymbolName,
  legacyCodeViewTypeName, legacyCodeViewFieldName } from "../../../../renderers/pe/legacy-codeview-kinds.js";

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
