import { NativeFormatFixtureWriter } from "./native-format-metadata-fixture.js";
import { createNativeFormatSignatureFixture } from "./native-format-signature-fixture.js";

export const createNativeFormatMemberFixture = () => {
  const signature = createNativeFormatSignatureFixture();
  const writer = new NativeFormatFixtureWriter();
  writer.bytes.splice(0, writer.bytes.length, ...signature.bytes);
  signature.labels.forEach((offset, name) => writer.labels.set(name, offset));
  writer.label("method-member");
  writer.unsigned(6);
  writer.unsigned(0);
  writer.handle(0x1a, "method-name");
  writer.handle(0x2b, "method");
  writer.collection([[0x31, "parameter"]]);
  writer.collection([[0x26, "generic"]]);
  writer.unsigned(0);
  writer.label("parameter");
  writer.unsigned(16);
  writer.unsigned(1);
  writer.handle(0x1a, "parameter-name");
  writer.unsigned(0);
  writer.unsigned(0);
  writer.label("generic");
  writer.unsigned(0);
  writer.unsigned(4);
  writer.unsigned(1);
  writer.handle(0x1a, "generic-name");
  writer.unsigned(1);
  writer.variantHandle(0x3d, "type");
  writer.unsigned(0);
  writeField(writer);
  writeProperty(writer);
  writer.label("event");
  writer.unsigned(0);
  writer.handle(0x1a, "event-name");
  writer.variantHandle(0x3d, "type");
  writer.collection([[0x2a, "semantics"]]);
  writer.unsigned(0);
  writer.string("method-name", "Convert");
  writer.string("parameter-name", "input");
  writer.string("generic-name", "T");
  writer.string("field-name", "Value");
  writer.string("property-name", "Item");
  writer.string("event-name", "Changed");
  return { bytes: Uint8Array.from(writer.bytes),
    handle: (name: string, type: number) => ({ type, offset: writer.labels.get(name)! }) };
};

const writeField = (writer: NativeFormatFixtureWriter): void => {
  writer.label("field");
  writer.unsigned(6);
  writer.handle(0x1a, "field-name");
  writer.handle(0x24, "field-signature");
  writer.unsigned(0);
  writer.unsigned(12);
  writer.unsigned(0);
  writer.label("field-signature");
  writer.variantHandle(0x3d, "type");
};

const writeProperty = (writer: NativeFormatFixtureWriter): void => {
  writer.label("property");
  writer.unsigned(0);
  writer.handle(0x1a, "property-name");
  writer.handle(0x34, "property-signature");
  writer.collection([[0x2a, "semantics"]]);
  writer.unsigned(0);
  writer.unsigned(0);
  writer.label("property-signature");
  writer.unsigned(0x20);
  writer.variantHandle(0x3d, "type");
  writer.unsigned(1);
  writer.variantHandle(0x2c, "method-variable");
  writer.label("semantics");
  writer.unsigned(2);
  writer.handle(0x28, "method-member");
};
