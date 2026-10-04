"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createCustomAttributes, type ClrMetadataReferenceGraph
} from "../../../../../../analyzers/pe/clr/metadata-custom-attributes.js";
import { ClrHeapReaders } from "../../../../../../analyzers/pe/clr/metadata-heaps.js";
import type {
  PeClrMemberReferenceInfo, PeClrMetadataIndex, PeClrTypeReferenceInfo, PeClrMethodSignature
} from "../../../../../../analyzers/pe/clr/types.js";

const CUSTOM_ATTRIBUTE_PROLOG = [0x01, 0x00]; // ECMA-335 II.23.3.
const TABLE_MEMBER_REF = 0x0a; // ECMA-335 II.22.25.
const serString = (text: string): number[] => {
  const bytes = [...new TextEncoder().encode(text)];
  return [bytes.length, ...bytes];
};
const u32le = (value: number): number[] => [
  value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff
];
void test("createCustomAttributes resolves constructor TypeRef parameters before decoding", () => {
  const issues: string[] = [];
  const memberRef: PeClrMemberReferenceInfo = {
    row: 1,
    name: ".ctor",
    parent: nullIndex(),
    parentName: "Microsoft.CodeAnalysis.ObjectTypeAttribute",
    signatureBlobIndex: 0,
    signature: {
      callingConvention: 0,
      parameterCount: 2,
      returnType: "void",
      parameterTypes: ["class TypeRef#1", "string[]"]
    }
  };
  const attributes = createCustomAttributes(
    [{
      Parent: nullIndex(),
      Type: { ...nullIndex(), table: "MemberRef", tableId: TABLE_MEMBER_REF, row: 1 },
      Value: 1
    }],
    createBlobHeapReaders([
      ...CUSTOM_ATTRIBUTE_PROLOG,
      ...serString("Microsoft.CodeAnalysis.SymbolKey"),
      ...u32le(1),
      ...serString("Declaration"),
      0, 0
    ], issues),
    {
      modules: [], assembly: null, assemblyRefs: [], typeRefs: [systemTypeRef()],
      typeDefs: [], methodDefs: [], memberRefs: [memberRef], moduleRefs: []
    }
  );

  assert.strictEqual(attributes[0]?.fixedArguments[0]?.value, "Microsoft.CodeAnalysis.SymbolKey");
  assert.strictEqual(attributes[0]?.fixedArguments[1]?.value, "Declaration");
  assert.strictEqual(attributes[0]?.issues, undefined);
});

const nullIndex = (): PeClrMetadataIndex => ({
  table: "null",
  tableId: -1,
  row: 0,
  raw: 0,
  valid: true
});

const systemTypeRef = (): PeClrTypeReferenceInfo => ({
  row: 1,
  name: "Type",
  namespace: "System",
  resolutionScope: nullIndex(),
  fullName: "System.Type"
});

const createBlobHeapReaders = (payload: number[], issues: string[]): ClrHeapReaders =>
  new ClrHeapReaders({
    strings: null,
    guid: null,
    blob: Uint8Array.of(0, payload.length, ...payload),
    userString: null
  }, issues);

const constructorMember = (parameterTypes: Array<string | null>): PeClrMemberReferenceInfo => ({
  row: 1, name: ".ctor", parent: nullIndex(), parentName: "Example.Attribute", signatureBlobIndex: 1,
  signature: { callingConvention: 0x20, parameterCount: parameterTypes.length,
    returnType: "void", parameterTypes }
});

const referenceGraph = (member: PeClrMemberReferenceInfo): ClrMetadataReferenceGraph => ({
  modules: [], assembly: null, assemblyRefs: [], typeRefs: [systemTypeRef()],
  typeDefs: [], methodDefs: [], memberRefs: [member], moduleRefs: []
});

const attributeRow = (constructor: PeClrMetadataIndex) => ({ Parent: nullIndex(), Type: constructor, Value: 1 });
const memberIndex = (): PeClrMetadataIndex => ({ ...nullIndex(), table: "MemberRef", tableId: 10, row: 1 });

const memberWithSignature = (signature: PeClrMethodSignature | undefined): PeClrMemberReferenceInfo => {
  const member = constructorMember([]);
  if (signature) member.signature = signature;
  else delete member.signature;
  return member;
};

for (const constructor of [nullIndex(), { ...memberIndex(), valid: false },
  { ...memberIndex(), row: 2 }, { ...memberIndex(), tableId: 4 }, { ...memberIndex(), row: 0 }]) {
  void test(`reports unavailable constructor ${JSON.stringify(constructor)}`, () => {
    const attributes = createCustomAttributes([attributeRow(constructor)],
      createBlobHeapReaders([1, 0, 0, 0], []), referenceGraph(constructorMember([])));
    assert.deepEqual(attributes[0]?.fixedArguments, []);
    assert.match(attributes[0]?.issues?.[0] ?? "", /signature is unavailable or malformed/);
  });
}

for (const signature of [undefined, { ...constructorMember([]).signature!, issues: ["truncated"] },
  { ...constructorMember([]).signature!, returnType: "i4" },
  { ...constructorMember([]).signature!, callingConvention: 0x30, genericParameterCount: 1 },
  { ...constructorMember([]).signature!, callingConvention: 8 }
] satisfies (PeClrMethodSignature | undefined)[]) {
  void test(`rejects invalid attribute constructor signature ${JSON.stringify(signature)}`, () => {
    const attributes = createCustomAttributes([attributeRow(memberIndex())],
      createBlobHeapReaders([1, 0, 0, 0], []), referenceGraph(memberWithSignature(signature)));
    assert.deepEqual(attributes[0]?.fixedArguments, []);
    assert.match(attributes[0]?.issues?.[0] ?? "", /signature is unavailable or malformed/);
  });
}

void test("resolves MethodDef constructors and preserves malformed cell warnings", () => {
  const references = referenceGraph(constructorMember([]));
  references.methodDefs = [{ row: 1, name: ".ctor", ownerType: "Example.Attribute",
    rva: 0, implFlags: 0, flags: 0, signatureBlobIndex: 1,
    signature: constructorMember([]).signature! }];
  const attributes = createCustomAttributes([
    attributeRow({ ...memberIndex(), table: "MethodDef", tableId: 6 }), { Parent: 0, Type: 0, Value: nullIndex() }
  ], createBlobHeapReaders([1, 0, 0, 0], []), references);
  assert.equal(attributes[0]?.attributeType, "Example.Attribute");
  assert.equal(attributes[0]?.issues, undefined);
  assert.deepEqual(attributes[0]?.parent, nullIndex());
  assert.equal(attributes[1]?.constructor?.valid, false);
  assert.deepEqual(attributes[1]?.parent, { ...nullIndex(), valid: false });
  assert.deepEqual(attributes.map(attribute => attribute.row), [1, 2]);
  assert.deepEqual(attributes.map(attribute => attribute.valueBlobIndex), [1, 0]);
});

void test("keeps external enums unresolved and does not mistake names for primitive types", () => {
  const attributes = createCustomAttributes([attributeRow(memberIndex())],
    createBlobHeapReaders([1, 0, 7, 0, 0, 0, 0, 0], []),
    referenceGraph(constructorMember(["valuetype TypeRef#1"])));
  assert.match(attributes[0]?.fixedArguments[0]?.type ?? "", /^enum TypeRef#1/);
  assert.match(attributes[0]?.issues?.[0] ?? "", /underlying type is unresolved/);
});

const enumReferenceGraph = (parameterTypes: string[]): ClrMetadataReferenceGraph => ({
  ...referenceGraph(constructorMember(parameterTypes)),
  typeRefs: [{ ...systemTypeRef(), name: "Enum", fullName: "System.Enum" },
    { ...systemTypeRef(), row: 2, name: "Mode", namespace: "Example", fullName: "Example.Mode" }],
  typeDefs: [{ row: 1, name: "Mode", namespace: "Example", fullName: "Example.Mode", flags: 0,
    extends: { ...nullIndex(), tableId: 1, row: 1 },
    fieldStart: 1, fieldEnd: 1, methodStart: 1, methodEnd: null }],
  fields: [{ row: 1, name: "value__", flags: 0, signatureBlobIndex: 0,
    signature: { callingConvention: 6, parameterCount: 0, returnType: "i1", parameterTypes: [] } }]
});

void test("uses the local enum field width for fixed values and arrays", () => {
  const attributes = createCustomAttributes([attributeRow(memberIndex())],
    createBlobHeapReaders([1, 0, 0xff, ...u32le(1), 0xfe, 0, 0], []),
    enumReferenceGraph(["valuetype TypeDef#1", "valuetype TypeDef#1[]"]));
  assert.deepEqual(attributes[0]?.fixedArguments.map(argument => argument.value), [-1, "-2"]);
  assert.equal(attributes[0]?.issues, undefined);
});

void test("does not apply a local enum width to an external enum with the same name", () => {
  const attributes = createCustomAttributes([attributeRow(memberIndex())],
    createBlobHeapReaders([1, 0, 0xff, 0, 0], []), enumReferenceGraph(["valuetype TypeRef#2"]));
  assert.match(attributes[0]?.issues?.[0] ?? "", /underlying type is unresolved/);
  assert.equal(attributes[0]?.fixedArguments[0]?.value, null);
});

void test("keeps invalid class references unresolved", () => {
  const attributes = createCustomAttributes([attributeRow(memberIndex())],
    createBlobHeapReaders([1, 0, 0, 0], []), referenceGraph(constructorMember(["class TypeRef#2"])));
  assert.match(attributes[0]?.issues?.[0] ?? "", /not supported/);
});

void test("reuses values for shared blobs and equivalent constructor parameter types", () => {
  const graph = referenceGraph(constructorMember(["i4"]));
  graph.memberRefs.push({ ...constructorMember(["i4"]), row: 2 }, { ...constructorMember(["u4"]), row: 3 });
  const attributes = createCustomAttributes([
    attributeRow(memberIndex()), attributeRow({ ...memberIndex(), row: 2 }),
    attributeRow({ ...memberIndex(), row: 3 }), attributeRow(memberIndex())
  ], createBlobHeapReaders([1, 0, ...u32le(254), 0, 0], []), graph);
  assert.strictEqual(attributes[0]!.fixedArguments, attributes[1]!.fixedArguments);
  assert.strictEqual(attributes[0]!.fixedArguments, attributes[3]!.fixedArguments);
  assert.deepEqual(attributes[0]!.fixedArguments, [{ type: "i4", value: 254 }]);
  assert.deepEqual(attributes[2]!.fixedArguments, [{ type: "u4", value: 254 }]);
});

void test("attributes cached malformed values to the correct metadata rows", () => {
  const graph = referenceGraph(constructorMember(["i4"]));
  const attributes = createCustomAttributes([attributeRow(memberIndex()), attributeRow(memberIndex())],
    createBlobHeapReaders([1, 0], []), graph);
  assert.match(attributes[0]!.issues![0]!, /CustomAttribute row 1.*truncated/);
  assert.match(attributes[1]!.issues![0]!, /CustomAttribute row 2.*truncated/);
});

void test("resolves shared constructor parameter types once within the parse", () => {
  const member = constructorMember(["i4"]);
  let reads = 0;
  Object.defineProperty(member.signature, "parameterTypes", { get: () => { reads++; return ["i4"]; } });
  const attributes = createCustomAttributes([attributeRow(memberIndex()), attributeRow(memberIndex())],
    createBlobHeapReaders([1, 0, ...u32le(7), 0, 0], []), referenceGraph(member));
  assert.deepEqual(attributes[0]!.fixedArguments, [{ type: "i4", value: 7 }]);
  assert.equal(reads, 1);
});

void test("keeps missing external enum reference identity in array diagnostics", () => {
  const attributes = createCustomAttributes([attributeRow(memberIndex())],
    createBlobHeapReaders([1, 0, ...u32le(1), 0, 0], []),
    referenceGraph(constructorMember(["valuetype TypeRef#2[]"])));
  assert.equal(attributes[0]!.fixedArguments[0]!.type, "enum TypeRef#2 (unresolved)[]");
  assert.match(attributes[0]!.issues![0]!, /underlying type is unresolved/);
});

void test("rejects unexpected constructor tables even when a MethodDef is available", () => {
  const graph = referenceGraph(constructorMember([]));
  graph.methodDefs = [{ row: 1, name: ".ctor", ownerType: "A", rva: 0, flags: 0,
    implFlags: 0, signatureBlobIndex: 1, signature: constructorMember([]).signature! }];
  const attributes = createCustomAttributes([attributeRow({ ...memberIndex(), tableId: 4 })],
    createBlobHeapReaders([1, 0, 0, 0], []), graph);
  assert.equal(attributes[0]!.attributeType, null);
  assert.match(attributes[0]!.issues![0]!, /signature is unavailable or malformed/);
});

void test("attributes absent blob warnings to the correct attribute field", () => {
  const issues: string[] = [];
  createCustomAttributes([{ ...attributeRow(memberIndex()), Value: 99 }],
    createBlobHeapReaders([1, 0, 0, 0], issues), referenceGraph(constructorMember([])));
  assert.deepEqual(issues, ["CustomAttribute row 1.Value has #Blob index 99, outside the heap."]);
});

for (const type of ["prefix class TypeRef#1", "class TypeRef#1 suffix"]) {
  void test(`rejects extra text around the attribute parameter type ${type}`, () => {
    const attributes = createCustomAttributes([attributeRow(memberIndex())],
      createBlobHeapReaders([1, 0, 0xff, 0, 0], []), referenceGraph(constructorMember([type])));
    assert.equal(attributes[0]!.fixedArguments[0]!.type, type);
    assert.match(attributes[0]!.issues![0]!, /not supported/);
  });
}

void test("resolves multiple-digit TypeRef rows for System.Type parameters", () => {
  const graph = referenceGraph(constructorMember(["class TypeRef#12"]));
  graph.typeRefs = Array.from({ length: 12 }, (_, index) => ({ ...systemTypeRef(), row: index + 1 }));
  const attributes = createCustomAttributes([attributeRow(memberIndex())],
    createBlobHeapReaders([1, 0, 0, 0, 0], []), graph);
  assert.deepEqual(attributes[0]!.fixedArguments, [{ type: "System.Type", value: "" }]);
  assert.equal(attributes[0]!.issues, undefined);
});
