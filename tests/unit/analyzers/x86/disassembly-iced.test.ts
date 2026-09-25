import assert from "node:assert/strict";
import { test } from "node:test";
import * as iced from "iced-x86-disasm";
import {
  isIcedX86Module,
  lookupIcedEnumValue
} from "../../../../analyzers/x86/disassembly-iced.js";

void test("accepts the installed decoder module", () => {
  assert.equal(isIcedX86Module(iced), true);
});

void test("rejects absent and non-object modules", () => {
  assert.equal(isIcedX86Module(undefined), false);
  assert.equal(isIcedX86Module(null), false);
  assert.equal(isIcedX86Module("iced"), false);
});

void test("rejects missing or malformed required enums", () => {
  assert.equal(isIcedX86Module({ ...iced, DecoderOptions: undefined }), false);
  assert.equal(isIcedX86Module({ ...iced, DecoderOptions: {} }), false);
  assert.equal(isIcedX86Module({ ...iced, Code: undefined }), false);
  assert.equal(isIcedX86Module({ ...iced, Code: { INVALID: "bad" } }), false);
  assert.equal(isIcedX86Module({ ...iced, CpuidFeature: undefined }), false);
  assert.equal(isIcedX86Module({ ...iced, FlowControl: undefined }), false);
  assert.equal(isIcedX86Module({ ...iced, OpKind: undefined }), false);
});

void test("rejects missing decoder and instruction constructors", () => {
  assert.equal(isIcedX86Module({ ...iced, Decoder: undefined }), false);
  assert.equal(isIcedX86Module({ ...iced, Instruction: undefined }), false);
});

void test("reads a numeric enum member by name", () => {
  assert.equal(lookupIcedEnumValue(iced.Register, "AX"), iced.Register.AX);
});

void test("ignores reverse mappings, absent names, and missing enum tables", () => {
  assert.equal(lookupIcedEnumValue(iced.Register, String(iced.Register.AX)), undefined);
  assert.equal(lookupIcedEnumValue(iced.Register, "missing"), undefined);
  assert.equal(lookupIcedEnumValue(undefined, "AX"), undefined);
});

void test("ignores a malformed enum getter", () => {
  const table = Object.defineProperty({}, "AX", {
    get() { throw new Error("invalid enum table"); }
  });
  assert.equal(lookupIcedEnumValue(table, "AX"), undefined);
});
