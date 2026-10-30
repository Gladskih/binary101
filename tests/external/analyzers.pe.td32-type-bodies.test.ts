import assert from "node:assert/strict";
import { test } from "node:test";
import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { parseTd32 } from "../../analyzers/pe/debug/td32.js";
import type { Td32TypeBody } from "../../analyzers/pe/debug/td32-type-body-types.js";
import { createExtraDebugPayloadSubject, identityRvaToOff } from "../fixtures/pe-debug-extra-payloads.js";

interface OracleFields {
  Attribute?: number | { PtrType: number; Mode: number; Attributes: number };
  Type?: number;
  PointedType?: number;
  ClassType?: number;
  PtrToDataMembAttrib?: number;
  RetType?: number;
  CallConv?: { Kind: number; Flags: number };
  ArgsRef?: number;
  ThisType?: number;
  NumArgs?: number;
  Args?: number | number[];
  ThisAdjust?: number;
}
interface OracleTypeBody { index: number; kind: number; fields: OracleFields; }
interface OracleClassType {
  index: number;
  fields: { Members: number; Flags: number; ContainingType: number;
    DerivationList: number; VTable: number; Size: string };
}
const pointerBody = (fields: OracleFields): Record<string, unknown> => {
  const attributes = fields.Attribute as { PtrType: number; Mode: number; Attributes: number };
  return { attributes: attributes.PtrType | attributes.Mode << 5 | attributes.Attributes << 8,
    targetType: fields.PointedType,
    ...(attributes.Mode === 2 || attributes.Mode === 3 ? {
      memberAttributes: fields.PtrToDataMembAttrib! & 0xffff, classType: fields.ClassType
    } : {}) };
};
const expectedBody = (kind: number, fields: OracleFields): Record<string, unknown> => {
  if (kind === 1) return { attributes: fields.Attribute as number, targetType: fields.Type };
  if (kind === 2) return pointerBody(fields);
  if (kind === 0x201) return { argumentTypes: fields.Args as number[] };
  const procedure = { returnType: fields.RetType,
    callingConvention: fields.CallConv!.Kind | fields.CallConv!.Flags << 6 };
  if (kind === 8) return { ...procedure, argumentList: fields.ArgsRef };
  assert.equal(kind, 9);
  return { ...procedure, classType: fields.ClassType, thisType: fields.ThisType,
    parameterCount: fields.NumArgs, argumentList: fields.Args as number, thisAdjustment: fields.ThisAdjust };
};

const assertBodies = (bodies: ReadonlyMap<number, Td32TypeBody | undefined>,
  references: readonly OracleTypeBody[]): void => {
  assert.equal(references.length, 16444);
  for (const reference of references) {
    const expected = expectedBody(reference.kind, reference.fields);
    assert.deepEqual(Object.fromEntries(Object.keys(expected).map(key =>
      [key, bodies.get(reference.index)![key as keyof Td32TypeBody]])),
    expected, `type index ${reference.index}`);
  }
};

const assertClasses = (bodies: ReadonlyMap<number, Td32TypeBody | undefined>,
  references: readonly OracleClassType[]): void => {
  assert.equal(references.length, 4322);
  for (const reference of references) {
    const body = bodies.get(reference.index)!;
    assert.deepEqual([body.fieldList, body.attributes, body.relation12, body.relation16,
      body.relation20, body.byteSize?.value], [reference.fields.Members, reference.fields.Flags,
      reference.fields.ContainingType, reference.fields.DerivationList, reference.fields.VTable,
      reference.fields.Size], `class index ${reference.index}`);
  }
};

// Unchanged C++Builder FB0A:
// https://github.com/AntonyFFC/arkanoid-game/blob/50d66b1b6306b3242f6f2f4cd71b9f75d3ac16e3/Project1.tds
// Oracle.cs invokes unchanged map2dbg 70cd89ff decoders. Its directory traversal is an adapter,
// not an independent framing oracle. Delphi-specific primitive names are not inferred here.
void test("real TD32 type bodies agree with unchanged map2dbg decoders", async () => {
  const path = resolve("scan-results/td32-public/arkanoid-Project1.tds");
  const oracle = JSON.parse(execFileSync(resolve("scan-results/td32-oracle.exe"),
    [resolve("scan-results/td32-upstream.dll"), path], { encoding: "utf8", maxBuffer: 32 * 1024 * 1024 })) as {
    typeBodies: OracleTypeBody[]; classTypes: OracleClassType[];
  };
  const subject = createExtraDebugPayloadSubject(await readFile(path));
  const parsed = await parseTd32(subject.file, subject.file.size, identityRvaToOff,
    0, subject.offset, subject.declaredSize, () => {});
  const bodies = new Map(parsed!.directories.flatMap(directory => directory.subsections.flatMap(section =>
    section.data?.kind === "types" ? section.data.records.map(record => [record.index, record.body] as const) : [])));
  assertBodies(bodies, oracle.typeBodies);
  assertClasses(bodies, oracle.classTypes);
});
