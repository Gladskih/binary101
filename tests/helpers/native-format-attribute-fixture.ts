import { NativeFormatFixtureWriter } from "./native-format-metadata-fixture.js";
import { nativeFormatWideBytes } from "./native-format-constant-fixture.js";

const writeConstructor = (writer: NativeFormatFixtureWriter): void => {
  writer.label("type");
  writer.unsigned(0);
  writer.handle(0x1a, "type-name");
  writer.label("definition");
  writer.unsigned(0);
  writer.unsigned(0);
  writer.unsigned(0);
  writer.handle(0x1a, "type-name");
  for (let index = 0; index < 12; index++) writer.unsigned(0);
  writer.label("constructor");
  writer.unsigned(0);
  writer.unsigned(0);
  writer.handle(0x1a, "constructor-name");
  for (let index = 0; index < 4; index++) writer.unsigned(0);
  writer.label("qualified");
  writer.handle(0x28, "constructor");
  writer.handle(0x3a, "definition");
  writer.label("member");
  writer.variantHandle(0x3d, "type");
  writer.handle(0x1a, "constructor-name");
  writer.unsigned(0);
};

const writeAttributes = (writer: NativeFormatFixtureWriter): void => {
  writer.label("attribute");
  writer.variantHandle(0x27, "member");
  writer.unsigned(5);
  writer.variantHandle(0x13, "long");
  writer.variantHandle(0x0c, "enum");
  writer.variantHandle(0x19, "strings");
  writer.variantHandle(0x3d, "type");
  writer.variantHandle(0x0b, "enum-array");
  writer.collection([[0x2e, "named-field"], [0x2e, "named-property"]]);
  writer.label("qualified-attribute");
  writer.variantHandle(0x36, "qualified");
  writer.unsigned(0);
  writer.unsigned(0);
  writer.label("named-field");
  writer.unsigned(1);
  writer.handle(0x1a, "field-name");
  writer.variantHandle(0x3d, "type");
  writer.variantHandle(0x11, "integer");
  writer.label("named-property");
  writer.unsigned(0);
  writer.handle(0x1a, "property-name");
  writer.variantHandle(0x3d, "type");
  writer.variantHandle(0x04, "boolean");
};

const writeValues = (writer: NativeFormatFixtureWriter): void => {
  writer.label("long");
  writer.bytes.push(...nativeFormatWideBytes(9007199254740993n));
  writer.label("integer");
  writer.unsigned(42);
  writer.label("boolean");
  writer.bytes.push(0);
  writer.label("enum");
  writer.variantHandle(0x11, "integer");
  writer.variantHandle(0x3d, "type");
  writer.label("enum-array");
  writer.variantHandle(0x3d, "type");
  writer.variantHandle(0x10, "integers");
  writer.label("integers");
  writer.unsigned(2);
  writer.unsigned(42);
  writer.unsigned(43);
  writer.label("strings");
  writer.unsigned(3);
  writer.variantHandle(0x1a, "text");
  writer.variantHandle(0x14, "null");
  writer.unsigned(0);
  writer.label("null");
  writer.string("text", "<hello>");
};

const writeDefaultOwners = (writer: NativeFormatFixtureWriter): void => {
  writer.label("field");
  writer.unsigned(0);
  writer.handle(0x1a, "field-name");
  writer.unsigned(0);
  writer.variantHandle(0x13, "long");
  writer.unsigned(0);
  writer.collection([[0x21, "attribute"]]);
  writer.label("property");
  writer.unsigned(0);
  writer.handle(0x1a, "property-name");
  writer.unsigned(0);
  writer.unsigned(0);
  writer.variantHandle(0x11, "integer");
  writer.collection([[0x21, "attribute"]]);
  writer.label("parameter");
  writer.unsigned(0);
  writer.unsigned(1);
  writer.handle(0x1a, "field-name");
  writer.variantHandle(0x04, "boolean");
  writer.collection([[0x21, "attribute"]]);
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
