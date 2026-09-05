"use strict";

const HANDLE_TYPES = {
  constantString: 0x1a,
  field: 0x23, // NativeFormatReaderCommonGen.cs, HandleType.Field (.NET 10).
  method: 0x28,
  namespace: 0x2f,
  scope: 0x38,
  type: 0x3a
} as const;

type HandlePatch = { index: number; type: number | null };

const encodeUnsigned = (value: number): number[] => {
  if (value < 0x80) return [value << 1];
  if (value < 0x4000) return [(value << 2 | 1) & 0xff, value >>> 6];
  return [0x0f, value & 0xff, value >>> 8 & 0xff, value >>> 16 & 0xff, value >>> 24];
};

class MetadataFixtureWriter {
  readonly bytes: number[] = [0xfd, 0xdf, 0xad, 0xde];
  readonly patches = new Map<string, HandlePatch[]>();
  readonly labels = new Map<string, number>();

  unsigned(value: number): void {
    this.bytes.push(...encodeUnsigned(value));
  }

  handle(_type: number, label?: string): void {
    const index = this.bytes.length;
    this.bytes.push(0x0f, 0, 0, 0, 0);
    if (!label) return;
    const offset = this.labels.get(label);
    if (offset == null) {
      this.patches.set(label, [...(this.patches.get(label) ?? []), { index, type: null }]);
      return;
    }
    this.patch({ index, type: null }, offset);
  }

  variantHandle(type: number, label: string): void {
    const index = this.bytes.length;
    this.bytes.push(0x0f, 0, 0, 0, 0);
    const offset = this.labels.get(label);
    if (offset == null) {
      this.patches.set(label, [...(this.patches.get(label) ?? []), { index, type }]);
      return;
    }
    this.patch({ index, type }, offset);
  }

  collection(entries: Array<[number, string]>): void {
    this.unsigned(entries.length);
    entries.forEach(([type, label]) => this.handle(type, label));
  }

  label(name: string): void {
    const offset = this.bytes.length;
    this.labels.set(name, offset);
    for (const patch of this.patches.get(name) ?? []) {
      this.patch(patch, offset);
    }
    this.patches.delete(name);
  }

  private patch(target: HandlePatch, offset: number): void {
    const token = target.type == null ? offset : (offset << 7) | target.type;
    this.bytes[target.index + 1] = token & 0xff;
    this.bytes[target.index + 2] = token >>> 8 & 0xff;
    this.bytes[target.index + 3] = token >>> 16 & 0xff;
    this.bytes[target.index + 4] = token >>> 24 & 0xff;
  }

  string(label: string, value: string): void {
    this.label(label);
    const encoded = new TextEncoder().encode(value);
    this.unsigned(encoded.length);
    this.bytes.push(...encoded);
  }
}

const emptyCollection = (writer: MetadataFixtureWriter): void => writer.unsigned(0);
const nilHandle = (writer: MetadataFixtureWriter): void => writer.unsigned(0);

const writeMethod = (writer: MetadataFixtureWriter, label: string, name: string): void => {
  writer.label(label);
  writer.unsigned(0x16);
  writer.unsigned(0);
  writer.handle(HANDLE_TYPES.constantString, `${label}-name`);
  nilHandle(writer);
  emptyCollection(writer);
  emptyCollection(writer);
  emptyCollection(writer);
  writer.string(`${label}-name`, name);
};

const writeType = (
  writer: MetadataFixtureWriter,
  label: string,
  name: string,
  namespaceLabel: string,
  enclosingLabel: string | null,
  nestedTypes: string[],
  methods: string[],
  fields: string[] = []
): void => {
  writer.label(label);
  writer.unsigned(1);
  nilHandle(writer);
  writer.handle(HANDLE_TYPES.namespace, namespaceLabel);
  writer.handle(HANDLE_TYPES.constantString, `${label}-name`);
  writer.unsigned(0);
  writer.unsigned(0);
  enclosingLabel ? writer.handle(HANDLE_TYPES.type, enclosingLabel) : nilHandle(writer);
  writer.collection(nestedTypes.map(item => [HANDLE_TYPES.type, item]));
  writer.collection(methods.map(item => [HANDLE_TYPES.method, item]));
  writer.collection(fields.map(item => [HANDLE_TYPES.field, item]));
  for (let index = 0; index < 5; index += 1) emptyCollection(writer);
  writer.string(`${label}-name`, name);
};

const writeScope = (writer: MetadataFixtureWriter, majorVersion: number, scopeCount: number): void => {
  writer.collection(Array.from({ length: scopeCount }, () => [HANDLE_TYPES.scope, "scope"]));
  writer.label("scope");
  writer.unsigned(0);
  writer.handle(HANDLE_TYPES.constantString, "assembly-name");
  writer.unsigned(0x8004);
  [majorVersion, 2, 3, 4].forEach(value => writer.unsigned(value));
  emptyCollection(writer);
  nilHandle(writer);
  writer.handle(HANDLE_TYPES.namespace, "root-namespace");
  nilHandle(writer);
  nilHandle(writer);
  emptyCollection(writer);
  writer.handle(HANDLE_TYPES.constantString, "module-name");
  writer.unsigned(16);
  for (let index = 0; index < 16; index += 1) writer.bytes.push(index);
  emptyCollection(writer);
};

const writeNamespaces = (
  writer: MetadataFixtureWriter,
  rootChildren: string[],
  demoChildren: string[]
): void => {
  writer.label("root-namespace");
  writer.variantHandle(HANDLE_TYPES.scope, "scope");
  writer.handle(HANDLE_TYPES.constantString, "empty-name");
  emptyCollection(writer);
  emptyCollection(writer);
  writer.collection(rootChildren.map(label => [HANDLE_TYPES.namespace, label]));
  writer.label("demo-namespace");
  writer.variantHandle(HANDLE_TYPES.namespace, "root-namespace");
  writer.handle(HANDLE_TYPES.constantString, "demo-name");
  writer.collection([[HANDLE_TYPES.type, "program-type"]]);
  emptyCollection(writer);
  writer.collection(demoChildren.map(label => [HANDLE_TYPES.namespace, label]));
  writer.label("inner-namespace");
  writer.variantHandle(HANDLE_TYPES.namespace, "demo-namespace");
  writer.handle(HANDLE_TYPES.constantString, "inner-name");
  writer.collection([[HANDLE_TYPES.type, "worker-type"]]);
  emptyCollection(writer);
  emptyCollection(writer);
};

const buildNativeFormatMetadataFixture = (
  majorVersion: number,
  rootChildren: string[],
  nestedTypes: string[],
  demoChildren: string[],
  methods: string[] = ["main-method"],
  fields: string[] = ["count-field", "name-field"],
  scopeCount = 1
): Uint8Array => {
  const writer = new MetadataFixtureWriter();
  writeScope(writer, majorVersion, scopeCount);
  writeNamespaces(writer, rootChildren, demoChildren);
  writeMethod(writer, "main-method", "Main");
  writeMethod(writer, "work-method", "Work");
  writeMethod(writer, "run-method", "Run");
  writeField(writer, "count-field", "Count");
  writeField(writer, "name-field", "<Name>k__BackingField");
  writeField(writer, "value-field", "Value");
  writeType(writer, "program-type", "Program", "demo-namespace", null,
    nestedTypes, methods, fields);
  writeType(writer, "nested-type", "Nested", "demo-namespace", "program-type", [],
    ["work-method"], ["value-field"]);
  writeType(writer, "worker-type", "Worker", "inner-namespace", null, [], ["run-method"]);
  writer.string("assembly-name", "HelloCSharp");
  writer.string("module-name", "HelloCSharp.dll");
  writer.string("empty-name", "");
  writer.string("demo-name", "Demo");
  writer.string("inner-name", "Inner");
  assertFixtureComplete(writer);
  return Uint8Array.from(writer.bytes);
};

export const createNativeFormatMetadataFixture = (majorVersion = 1): Uint8Array =>
  buildNativeFormatMetadataFixture(
    majorVersion,
    ["demo-namespace"],
    ["nested-type"],
    ["inner-namespace"]
  );

export const createNativeFormatMetadataWithRepeatedMembersFixture = (count: number): Uint8Array =>
  buildNativeFormatMetadataFixture(1, ["demo-namespace"], ["nested-type"], ["inner-namespace"],
    Array.from({ length: count }, () => "main-method"),
    Array.from({ length: count }, () => "count-field"));

export const createNativeFormatMetadataWithRepeatedScopesFixture = (count: number): Uint8Array =>
  buildNativeFormatMetadataFixture(1, ["demo-namespace"], ["nested-type"], ["inner-namespace"],
    ["main-method"], ["count-field", "name-field"], count);

export const createNativeFormatMetadataWithTypeCycleFixture = (): Uint8Array =>
  buildNativeFormatMetadataFixture(1, ["demo-namespace"], ["program-type"], ["inner-namespace"]);

export const createNativeFormatMetadataWithDuplicateReferencesFixture = (): Uint8Array =>
  buildNativeFormatMetadataFixture(
    1,
    ["demo-namespace", "demo-namespace"],
    ["nested-type", "nested-type"],
    ["inner-namespace"]
  );

export const createNativeFormatMetadataWithNamespaceCycleFixture = (): Uint8Array =>
  buildNativeFormatMetadataFixture(
    1,
    ["demo-namespace"],
    ["nested-type"],
    ["inner-namespace", "root-namespace"]
  );

const assertFixtureComplete = (writer: MetadataFixtureWriter): void => {
  if (writer.patches.size) throw new Error(`Unresolved fixture labels: ${[...writer.patches.keys()]}`);
};

const writeField = (writer: MetadataFixtureWriter, label: string, name: string): void => {
  // Field: flags, name, signature, default value, offset, custom attributes.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Metadata/NativeFormat/NativeFormatReaderGen.cs
  writer.label(label);
  writer.unsigned(0x16); // FieldAttributes.Public | Static.
  writer.handle(HANDLE_TYPES.constantString, `${label}-name`);
  nilHandle(writer);
  nilHandle(writer);
  writer.unsigned(0);
  emptyCollection(writer);
  writer.string(`${label}-name`, name);
};
