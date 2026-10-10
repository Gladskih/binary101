import { nativeFormatFixtureKinds as kinds, nativeFormatSampleInteger } from "./native-format-wire-fixture.js";
import { NativeFormatFixtureWriter } from "./native-format-metadata-fixture.js";
import { nativeFormatWideBytes } from "./native-format-constant-fixture.js";

const writeConstructor = (writer: NativeFormatFixtureWriter): void => {
  // Record field order: TypeReference, TypeDefinition, Method, QualifiedMethod,
  // MemberReference constructors in NativeFormatReaderGen.cs.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Metadata/NativeFormat/NativeFormatReaderGen.cs
  writer.label("type");
  writer.unsigned(0);
  writer.handle(kinds.string, "type-name");
  writer.label("definition");
  writer.unsigned(0);
  writer.unsigned(0);
  writer.unsigned(0);
  writer.handle(kinds.string, "type-name");
  for (const _field of ["size", "packingSize", "enclosingType", "nestedTypes", "methods", "fields",
    "properties", "events", "genericParameters", "interfaces", "customAttributes"]) writer.unsigned(0);
  writer.label("constructor");
  writer.unsigned(0);
  writer.unsigned(0);
  writer.handle(kinds.string, "constructor-name");
  for (const _field of ["signature", "parameters", "genericParameters", "customAttributes"]) writer.unsigned(0);
  writer.label("qualified");
  writer.handle(kinds.method, "constructor");
  writer.handle(kinds.typeDefinition, "definition");
  writer.label("member");
  writer.variantHandle(kinds.typeReference, "type");
  writer.handle(kinds.string, "constructor-name");
  writer.unsigned(0);
};

const writeAttributes = (writer: NativeFormatFixtureWriter): void => {
  // Five fixed arguments: long, enum, strings, Type, enum array. NamedArgument
  // member kinds are Field=1 and Property=0 in NativeFormatReaderCommonGen.cs.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Metadata/NativeFormat/NativeFormatReaderCommonGen.cs
  writer.label("attribute");
  writer.variantHandle(kinds.member, "member");
  writer.unsigned(5);
  writer.variantHandle(kinds.int64, "long");
  writer.variantHandle(kinds.enum, "enum");
  writer.variantHandle(kinds.stringArray, "strings");
  writer.variantHandle(kinds.typeReference, "type");
  writer.variantHandle(kinds.enumArray, "enum-array");
  writer.collection([[kinds.namedArgument, "named-field"], [kinds.namedArgument, "named-property"]]);
  writer.label("qualified-attribute");
  writer.variantHandle(kinds.qualifiedMethod, "qualified");
  writer.unsigned(0);
  writer.unsigned(0);
  writer.label("named-field");
  writer.unsigned(1);
  writer.handle(kinds.string, "field-name");
  writer.variantHandle(kinds.typeReference, "type");
  writer.variantHandle(kinds.int32, "integer");
  writer.label("named-property");
  writer.unsigned(0);
  writer.handle(kinds.string, "property-name");
  writer.variantHandle(kinds.typeReference, "type");
  writer.variantHandle(kinds.boolean, "boolean");
};

const writeValues = (writer: NativeFormatFixtureWriter): void => {
  writer.label("long");
  // First integer above the exact binary64 range; must retain its full decimal value.
  writer.bytes.push(...nativeFormatWideBytes(2n ** 53n + 1n));
  writer.label("integer");
  writer.unsigned(nativeFormatSampleInteger);
  writer.label("boolean");
  writer.bytes.push(0);
  writer.label("enum");
  writer.variantHandle(kinds.int32, "integer");
  writer.variantHandle(kinds.typeReference, "type");
  writer.label("enum-array");
  writer.variantHandle(kinds.typeReference, "type");
  writer.variantHandle(kinds.int32Array, "integers");
  writer.label("integers");
  writer.unsigned(2);
  writer.unsigned(nativeFormatSampleInteger);
  writer.unsigned(nativeFormatSampleInteger + 1);
  writer.label("strings");
  writer.unsigned(3);
  writer.variantHandle(kinds.string, "text");
  writer.variantHandle(kinds.reference, "null");
  writer.unsigned(0);
  writer.label("null");
  writer.string("text", "<hello>");
};

const writeDefaultOwners = (writer: NativeFormatFixtureWriter): void => {
  writer.label("field");
  writer.unsigned(0);
  writer.handle(kinds.string, "field-name");
  writer.unsigned(0);
  writer.variantHandle(kinds.int64, "long");
  writer.unsigned(0);
  writer.collection([[kinds.attribute, "attribute"]]);
  writer.label("property");
  writer.unsigned(0);
  writer.handle(kinds.string, "property-name");
  writer.unsigned(0);
  writer.unsigned(0);
  writer.variantHandle(kinds.int32, "integer");
  writer.collection([[kinds.attribute, "attribute"]]);
  writer.label("parameter");
  writer.unsigned(0);
  writer.unsigned(1);
  writer.handle(kinds.string, "field-name");
  writer.variantHandle(kinds.boolean, "boolean");
  writer.collection([[kinds.attribute, "attribute"]]);
};

export const createNativeFormatAttributeFixture = () => {
  const writer = new NativeFormatFixtureWriter();
  writeConstructor(writer);
  writeAttributes(writer);
  writeValues(writer);
  writeDefaultOwners(writer);
  writer.string("type-name", "ExampleAttribute");
  writer.string("constructor-name", ".ctor");
  writer.string("field-name", "Number");
  writer.string("property-name", "Enabled");
  return { bytes: Uint8Array.from(writer.bytes),
    handle: (name: string, type: number) => ({ type, offset: writer.labels.get(name)! }) };
};
