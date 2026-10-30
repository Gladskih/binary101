import assert from "node:assert/strict";
import { test } from "node:test";
import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { parseTd32 } from "../../analyzers/pe/debug/td32.js";
import type { Td32TypeBody } from "../../analyzers/pe/debug/td32-type-body-types.js";
import type { Td32TypeField } from "../../analyzers/pe/debug/td32-type-member-types.js";
import { createExtraDebugPayloadSubject, identityRvaToOff } from "../fixtures/pe-debug-extra-payloads.js";

interface Attributes { Access: number; MProp: number; Attributes: number; }
interface FieldValues {
  Type?: number; Class?: number; List?: number; NestedType?: number;
  Name?: string; Attributes?: Attributes; Attribute?: Attributes; Offset?: string; BrowserOffset?: number;
}
interface NativeField { kind: number; fields: FieldValues; }
interface NativeMethods { Methods: { Attributes: Attributes; Func: number;
  BrowserOffset: number; VTabOffset: number }[]; }
interface NativeProperty { Type: number; Flags: number; IndexType: number;
  PropertyIndex: number; Reader?: string; Writer?: string; ReadSlot: number; WriteSlot: number; }
interface NativeType { index: number; kind: number; fields: NativeField[] | NativeMethods | NativeProperty; }
const attributes = (value: Attributes): number => value.Access | value.MProp << 2 | value.Attributes << 5;

const assertField = (actual: Td32TypeField, reference: FieldValues, names: readonly string[]): void => {
  assert.equal(actual.targetType, reference.Type ?? reference.Class ?? reference.List ?? reference.NestedType);
  if (reference.Name !== undefined) assert.equal(names[actual.nameIndex! - 1], reference.Name);
  if (reference.Attributes) assert.equal(actual.attributes, attributes(reference.Attributes));
  if (reference.Attribute) assert.equal(actual.attributes, attributes(reference.Attribute));
  if (reference.Offset !== undefined) assert.equal(actual.offset?.value, reference.Offset);
  if (reference.BrowserOffset !== undefined) assert.equal(actual.browserOffset, reference.BrowserOffset);
};
const assertMethods = (body: Td32TypeBody, fields: NativeMethods): void => {
  assert.deepEqual(body.methods, fields.Methods.map(method => ({
    attributes: attributes(method.Attributes), methodType: method.Func, browserOffset: method.BrowserOffset,
    ...([4, 6].includes(method.Attributes.MProp) ? { vtableOffset: method.VTabOffset } : {})
  })));
};
const assertProperty = (body: Td32TypeBody, fields: NativeProperty, names: readonly string[]): void => {
  assert.deepEqual([body.underlyingType, body.attributes, body.indexType, body.propertyIndex],
    [fields.Type, fields.Flags, fields.IndexType, fields.PropertyIndex]);
  if (fields.Flags & 2) assert.equal(body.readerValue, fields.ReadSlot);
  else assert.equal(names[body.readerValue! - 1] ?? null, fields.Reader ?? null);
  if (fields.Flags & 4) assert.equal(body.writerValue, fields.WriteSlot);
  else assert.equal(names[body.writerValue! - 1] ?? null, fields.Writer ?? null);
};
const assertAdditionalTypes = (bodies: ReadonlyMap<number, Td32TypeBody | undefined>,
  references: readonly NativeType[], names: readonly string[], translatedNames: readonly string[]): void => {
  let fields = 0;
  let methods = 0;
  let properties = 0;
  for (const reference of references) {
    const body = bodies.get(reference.index)!;
    if (reference.kind === 0x204) {
      const actual = body.fields!.filter(field => [0x400, 0x406, 0x408, 0x409].includes(field.type));
      const expected = reference.fields as NativeField[];
      assert.equal(actual.length, expected.length);
      actual.forEach((field, index) => assertField(field, expected[index]!.fields, translatedNames));
      fields += actual.length;
    } else if (reference.kind === 0x207) {
      assertMethods(body, reference.fields as NativeMethods);
      methods += body.methods!.length;
    } else {
      assertProperty(body, reference.fields as NativeProperty, names);
      properties++;
    }
  }
  assert.deepEqual({ fields, methods, properties }, { fields: 16769, methods: 5728, properties: 804 });
};

// The adapter invokes unchanged Mem*.Read/TypMList.Read/TypPasProperty.Read methods at
// https://github.com/andremussche/map2dbg/tree/70cd89ff693cd622215309b0acb4326e530e7884/tds2pdb
// Inline-only fields are framed by the adapter, not claimed as independent decoding.
void test("real FB0A members, methods and properties match unchanged native body readers", async () => {
  const path = resolve("scan-results/td32-public/arkanoid-Project1.tds");
  const oracle = JSON.parse(execFileSync(resolve("scan-results/td32-oracle.exe"),
    [resolve("scan-results/td32-upstream.dll"), path], { encoding: "utf8", maxBuffer: 32 * 1024 * 1024 })) as {
    additionalTypes: NativeType[]; names: string[]; translatedNames: string[];
  };
  const subject = createExtraDebugPayloadSubject(await readFile(path));
  const parsed = await parseTd32(subject.file, subject.file.size, identityRvaToOff,
    0, subject.offset, subject.declaredSize, () => {});
  const bodies = new Map(parsed!.directories.flatMap(directory => directory.subsections.flatMap(section =>
    section.data?.kind === "types" ? section.data.records.map(record => [record.index, record.body] as const) : [])));
  assertAdditionalTypes(bodies, oracle.additionalTypes, oracle.names, oracle.translatedNames);
});
