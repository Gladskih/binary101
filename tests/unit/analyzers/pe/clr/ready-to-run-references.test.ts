import assert from "node:assert/strict";
import { test } from "node:test";
import { validateReadyToRunReferences } from
  "../../../../../analyzers/pe/clr/ready-to-run-references.js";
import type { PeClrReadyToRunSection } from
  "../../../../../analyzers/pe/clr/ready-to-run-types.js";

const functions: PeClrReadyToRunSection = { type: 102, name: "RuntimeFunctions", rva: 0, size: 24 };
const methods = (index: number): PeClrReadyToRunSection => ({
  type: 103, name: "MethodDefEntryPoints", rva: 0, size: 0,
  decoded: { kind: "methods", methods: [
    { methodRid: 1, runtimeFunctionIndex: index, fixupOffset: null }
  ] }
});
const hotCold = (cold: number, hot: number): PeClrReadyToRunSection => ({
  type: 120, name: "HotColdMap", rva: 0, size: 8,
  decoded: { kind: "hot-cold", entries: [{ coldRuntimeFunction: cold, hotRuntimeFunction: hot }] }
});

void test("accepts valid method and hot/cold indices", () => {
  const issues: string[] = [];

  validateReadyToRunReferences([functions, methods(1), hotCold(0, 1)], 0x8664, issues);

  assert.deepEqual(issues, []);
});

void test("reports missing indices including the exact exclusive boundary", () => {
  const methodIssues: string[] = [];
  const coldIssues: string[] = [];
  const hotIssues: string[] = [];

  validateReadyToRunReferences([functions, methods(2)], 0x8664, methodIssues);
  validateReadyToRunReferences([functions, hotCold(2, 0)], 0x8664, coldIssues);
  validateReadyToRunReferences([functions, hotCold(0, 2)], 0x8664, hotIssues);

  assert.match(methodIssues.join(), /missing runtime-function index/);
  assert.deepEqual(coldIssues, methodIssues);
  assert.deepEqual(hotIssues, methodIssues);
});

void test("warns about partial runtime functions and skips unresolved targets", () => {
  const issues: string[] = [];
  const unresolved: string[] = [];

  validateReadyToRunReferences([{ ...functions, size: 23 }], 0x8664, issues);
  validateReadyToRunReferences([functions, methods(999)], undefined, unresolved);
  validateReadyToRunReferences([methods(999)], 0x8664, unresolved);

  assert.deepEqual(issues, ["RuntimeFunctions ends with an incomplete entry."]);
  assert.deepEqual(unresolved, []);
});

void test("detects invalid indices among otherwise valid entries", () => {
  const methodIssues: string[] = [];
  const hotColdIssues: string[] = [];

  validateReadyToRunReferences([functions, { ...methods(0), decoded: { kind: "methods", methods: [
    { methodRid: 1, runtimeFunctionIndex: 0, fixupOffset: null },
    { methodRid: 2, runtimeFunctionIndex: 2, fixupOffset: null }
  ] } }], 0x8664, methodIssues);
  validateReadyToRunReferences([functions, { ...hotCold(0, 1), decoded: { kind: "hot-cold", entries: [
    { coldRuntimeFunction: 0, hotRuntimeFunction: 1 },
    { coldRuntimeFunction: 2, hotRuntimeFunction: 0 }
  ] } }], 0x8664, hotColdIssues);

  assert.match(methodIssues.join(), /missing runtime-function index/);
  assert.deepEqual(hotColdIssues, methodIssues);
});
