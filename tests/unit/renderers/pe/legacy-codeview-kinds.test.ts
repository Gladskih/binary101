import assert from "node:assert/strict";
import { test } from "node:test";
import { legacyCodeViewSubsectionName, legacyCodeViewSymbolName,
  legacyCodeViewTypeName, legacyCodeViewFieldName } from "../../../../renderers/pe/legacy-codeview-kinds.js";

void test("C6 kinds use their own namespace, retaining offset widths and unknown values", () => {
  assert.equal(legacyCodeViewSubsectionName(0x101), "Modules (C6)");
  assert.equal(legacyCodeViewSubsectionName(0x109), "Source lines with segments (C6)");
  assert.equal(legacyCodeViewSymbolName(1, "c6"), "Procedure (16-bit offsets)");
  assert.equal(legacyCodeViewSymbolName(0x84, "c6"), "Stack variable (32-bit offsets)");
  assert.equal(legacyCodeViewSymbolName(2, "c6"), "Scope end");
  assert.equal(legacyCodeViewSymbolName(99, "c6"), "C6 symbol record 0x63");
  assert.equal(legacyCodeViewTypeName(93, "c6"), "Type alias");
  assert.equal(legacyCodeViewTypeName(127, "c6"), "Type or member list");
  assert.equal(legacyCodeViewTypeName(255, "c6"), "C6 type record 0xff");
});

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

for (const [types, name] of [
  [[0x1019], "Annotations"], [[0x113d], "Environment"], [[0x1161], "PDB mapping"],
  [[0x101a, 0x112a], "Global managed procedure"], [[0x101b, 0x112b], "Local managed procedure"],
  [[0x1022, 0x111e], "Managed frame-relative variable"], [[0x1023, 0x111f], "Managed register variable"],
  [[0x1024, 0x1120], "Managed slot variable"], [[0x1025, 0x1027, 0x1121, 0x1123], "Managed multi-register variable"],
  [[0x1026, 0x1122], "Managed register-relative variable"], [[0x112e], "Attributed frame-relative variable"],
  [[0x112f], "Attributed register variable"], [[0x1130], "Attributed register-relative variable"],
  [[0x1131], "Attributed multi-register variable"], [[0x1148], "Local MIPS procedure"],
  [[0x1149], "Global MIPS procedure"], [[0x114a], "Local IA64 procedure"], [[0x114b], "Global IA64 procedure"],
  [[0x1151, 0x1162, 0x1164], "Global HLSL data"], [[0x1152, 0x1163, 0x1165], "Local HLSL data"],
  [[0x1153], "File-static variable"], [[0x1154], "Group-shared local variable"],
  [[0x1155, 0x1156], "Local DPC procedure"], [[0x1160], "Mini-PDB symbol reference"],
  [[0x1169], "Hot-patch function"], [[0x1171], "Indirect register-relative variable"]
] as const) for (const type of types) {
  void test(`CodeView additional symbol ${type} has a readable category`, () => {
    assert.equal(legacyCodeViewSymbolName(type), name);
  });
}
