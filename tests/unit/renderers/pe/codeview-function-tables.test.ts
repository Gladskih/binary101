import assert from "node:assert/strict";
import { test } from "node:test";
import { buildCodeViewFunctionTables } from "../../../../renderers/pe/codeview-function-tables.js";
import { readLegacyCodeViewModuleTypes } from "../../../../analyzers/pe/debug/legacy-codeview-type-records.js";
import { codeViewCallableStream, codeViewInfoWithTypes } from "../../../fixtures/pe-codeview-callables.js";
import { legacyReader } from "../../../fixtures/pe-legacy-codeview.js";

void test("CodeView function tables show named signatures and calling conventions without address matrices", async () => {
  const data = await readLegacyCodeViewModuleTypes(legacyReader(codeViewCallableStream()));
  const tables = buildCodeViewFunctionTables({ signature: "NB09", directories: [{ flags: 0,
    subsections: [{ type: 0x121, module: 1, offset: 0, size: 0, data }] }] });
  assert.equal(tables[0]?.key, "functions");
  assert.equal(tables[0]?.title, "Function type signatures");
  assert.deepEqual(tables[0]?.columns, ["Directory", "Module", "Function / type", "Return type",
    "Parameters", "Declared parameters", "Calling convention", "Properties"]);
  assert.deepEqual(tables[0]?.rows, [["1", "1", "<convert>", "int32", "int32, float64",
    "2", "stdcall (near)", "C++ UDT return"]]);
});

void test("CodeView empty procedure options read as none and a nonfinal no-type argument is not variadic", () => {
  const tables = buildCodeViewFunctionTables(codeViewInfoWithTypes([
    { type: 0x1201, index: 0x1000, shape: { kind: "arguments", types: [0, 0x74] } },
    { type: 0x1008, index: 0x1001, shape: { kind: "procedure", returnType: 3,
      parameterCount: 2, argumentList: 0x1000, callingConvention: 0, attributes: 0 } }
  ]));
  assert.deepEqual(tables[0]?.rows[0], ["1", "1", "Function type #4097", "void", "no type, int32",
    "2", "cdecl (near)", "none"]);
});

void test("CodeView source calling conventions retain every published CV_call_e value", () => {
  // Microsoft cvconst.h, CV_call_e (0x00..0x18, with reserved slot 0x06).
  const expected = ["cdecl (near)", "cdecl (far)", "Pascal (near)", "Pascal (far)",
    "fastcall (near)", "fastcall (far)", "reserved", "stdcall (near)", "stdcall (far)",
    "syscall (near)", "syscall (far)", "thiscall", "MIPS", "generic", "Alpha", "PowerPC", "SuperH",
    "ARM", "AM33", "TriCore", "SuperH-5", "M32R", "CLR", "always inline", "vectorcall"];
  const tables = buildCodeViewFunctionTables(codeViewInfoWithTypes(expected.map((_, callingConvention) => ({
    type: 0x1008, index: 0x1000 + callingConvention, shape: { kind: "procedure", returnType: 3,
      parameterCount: 0, argumentList: 0x2000, callingConvention, attributes: 0 }
  }))));
  assert.deepEqual(tables[0]?.rows.map(row => row[6]), expected);
});

void test("CodeView function tables retain anonymous signatures, variadic markers and malformed references", () => {
  const tables = buildCodeViewFunctionTables(codeViewInfoWithTypes([
    { type: 0x1201, index: 0x1000, shape: { kind: "arguments", types: [0x74, 0] } },
    { type: 0x1008, index: 0x1001, shape: { kind: "procedure", returnType: 3, parameterCount: 2,
      argumentList: 0x1000, callingConvention: 255, attributes: 0x84 } },
    { type: 0x1009, shape: { kind: "memberFunction", returnType: 0x74, classType: 0x2000,
      thisType: 0, thisAdjustment: -8, parameterCount: 1, argumentList: 0x2001, callingConvention: 11, attributes: 2 } }
  ]));
  assert.deepEqual(tables[0]?.rows, [
    ["1", "1", "Function type #4097", "void", "int32, ...", "2", "unknown convention 255",
      "constructor with virtual bases; unknown attributes 0x80"],
    ["1", "1", "Unresolved function type", "int32", "unresolved argument list #8193", "1", "thiscall",
      "constructor; class unresolved type #8192; this: no type; this adjustment: -8 bytes"]
  ]);
});

void test("CodeView member IDs retain class qualification and empty argument lists", () => {
  const tables = buildCodeViewFunctionTables(codeViewInfoWithTypes([
    { type: 0x1505, index: 0x1000, name: "Packet" },
    { type: 0x1201, index: 0x1001, shape: { kind: "arguments", types: [] } },
    { type: 0x1009, index: 0x1002, shape: { kind: "memberFunction", returnType: 0x74,
      classType: 0x1000, thisType: 0x1000, thisAdjustment: 0, parameterCount: 0,
      argumentList: 0x1001, callingConvention: 0, attributes: 0 } },
    { type: 0x1602, index: 0x1003, strings: ["read"], shape: {
      kind: "memberFunctionId", classType: 0x1000, functionType: 0x1002 } }
  ]));
  assert.deepEqual(tables[0]?.rows[0], ["1", "1", "Packet::read", "int32", "(no parameters)", "0",
    "cdecl (near)", "class Packet; this: Packet; this adjustment: 0 bytes"]);
});

void test("CodeView function IDs never silently bind to ambiguous or non-callable types", () => {
  const tables = buildCodeViewFunctionTables(codeViewInfoWithTypes([
    { type: 0x1008, index: 0x1000, shape: { kind: "procedure", returnType: 3,
      parameterCount: 0, argumentList: 0x1001, callingConvention: 0, attributes: 0 } },
    { type: 0x1201, index: 0x1000, shape: { kind: "arguments", types: [] } },
    { type: 0x1601, index: 0x1002, strings: ["ambiguous"], shape: {
      kind: "functionId", scopeId: 0x1010, functionType: 0x1000 } },
    { type: 0x1601, index: 0x1003, shape: { kind: "functionId", scopeId: 0, functionType: 0x1001 } }
  ]));
  assert.equal(tables[0]?.rows[0]?.[2], "Ambiguous function type #4096");
  assert.deepEqual(tables[0]?.rows[1], ["1", "1", "scope #4112::ambiguous", "unresolved function type #4096",
    "unknown", "unknown", "unknown", "Function type is missing, ambiguous, or not callable."]);
  assert.equal(tables[0]?.rows[2]?.[2], "(unnamed function)");
});

void test("CodeView function tables omit sources without callable metadata", () => {
  assert.deepEqual(buildCodeViewFunctionTables({ signature: "NB02", directories: [{ flags: 0, subsections: [
    { type: 0x103, module: 1, offset: 0, size: 0, data: { kind: "types", encoding: "c6", records: [] } }
  ] }] }), []);
});
