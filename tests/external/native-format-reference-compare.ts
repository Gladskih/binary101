import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { NativeFormatReader, type NativeFormatLayout } from "../../analyzers/native-aot/native-format-reader.js";
import { NativeFormatStore } from "../../analyzers/native-aot/native-format-store.js";
import { nativeFormatSchemas } from "../../analyzers/native-aot/native-format-schema.js";

const aliases: Readonly<Record<string, string>> = {
  element: "ElementType", modifier: "ModifierType", implementationFlags: "ImplFlags",
  attributes: "CustomAttributes", semantics: "MethodSemantics", major: "MajorVersion",
  minor: "MinorVersion", build: "BuildNumber", revision: "RevisionNumber",
  rootNamespace: "RootNamespaceDefinition", globalType: "GlobalModuleType",
  moduleAttributes: "ModuleCustomAttributes", namespace: "NamespaceDefinition",
  arguments: "GenericTypeArguments", types: "TypeDefinitions", forwarders: "TypeForwarders",
  children: "NamespaceDefinitions"
};

interface ReferenceRecord {
  type: number;
  offset: number;
  fields: Record<string, unknown>;
}

const referenceField = (type: number, name: string): string => {
  if (name === "attributes" && type === 0x2a) return "Attributes";
  if (name === "parent") return type === 0x27 ? "Parent" :
    type === 0x3d ? "ParentNamespaceOrType" : "ParentScopeOrNamespace";
  if (name === "name" && type === 0x3d) return "TypeName";
  return Object.hasOwn(aliases, name) ? aliases[name]! : name[0]!.toUpperCase() + name.slice(1);
};

const expectedConstantField = (type: number, value: unknown): unknown => {
  if (Array.isArray(value)) return value.map(item => expectedConstantField(type, item));
  if (typeof value === "boolean") return Number(value);
  if ([0x08, 0x07].includes(type)) return (value as string).charCodeAt(0);
  if ([0x16, 0x15].includes(type)) return Number(value) & 255;
  return value;
};

const compareRecords = (store: NativeFormatStore, reference: ReferenceRecord[]) => {
  let records = 0;
  let fields = 0;
  for (const row of reference) {
    const schema = nativeFormatSchemas[row.type];
    if (!schema) continue;
    const record = store.record(row);
    for (const [name, encoding] of schema) {
      const actual = record.values[name];
      const value = row.fields[referenceField(row.type, name)];
      const expected = encoding === "handles" ? (value as { offset: number }[])
        .filter(handle => handle.offset !== 0) : expectedConstantField(row.type, value);
      assert.deepEqual(row.type === 0x1a ? new TextDecoder().decode(actual as Uint8Array) :
        actual instanceof Uint8Array ? [...actual] : actual,
        expected, `${row.type}:${row.offset} ${name}`);
      fields += 1;
    }
    records += 1;
  }
  assert.equal(store.warnings.size, 0, [...store.warnings].join("\n"));
  return { records, fields };
};

export const compareNativeFormatReference = async (
  blobPath: string, referencePath: string, layout: NativeFormatLayout = "dotnet10"
) => {
  const reference = JSON.parse(await readFile(referencePath, "utf8")) as ReferenceRecord[];
  return compareRecords(new NativeFormatStore(new NativeFormatReader(
    new Uint8Array(await readFile(blobPath)), layout), new Set()), reference);
};
