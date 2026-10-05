import { NativeFormatFixtureWriter } from "./native-format-metadata-fixture.js";

const writeReferences = (writer: NativeFormatFixtureWriter): void => {
  // Explicit handle kinds and field order are independent oracles from NativeFormatReaderGen.cs.
  writer.label("type");
  writer.variantHandle(0x30, "namespace");
  writer.handle(0x1a, "type-name");
  writer.label("namespace");
  writer.unsigned(0);
  writer.handle(0x1a, "namespace-name");
  writer.label("variable");
  writer.unsigned(0);
  writer.label("method-variable");
  writer.unsigned(1);
};

const writeElementSignatures = (writer: NativeFormatFixtureWriter): void => {
  writer.label("array");
  writer.variantHandle(0x3d, "type");
  writer.label("byref");
  writer.variantHandle(0x3f, "variable");
  writer.label("pointer");
  writer.variantHandle(0x3d, "type");
  writer.label("multi-array");
  writer.variantHandle(0x3d, "type");
  writer.unsigned(2);
  writer.unsigned(1);
  writer.unsigned(3);
  writer.unsigned(1);
  writer.bytes.push(0xfe); // DecodeSigned: -1 in its one-byte representation.
  writer.label("instantiation");
  writer.variantHandle(0x3d, "type");
  writer.unsigned(2);
  writer.variantHandle(0x3f, "variable");
  writer.variantHandle(0x2c, "method-variable");
};

const writeMethodSignatures = (writer: NativeFormatFixtureWriter): void => {
  writer.label("modified");
  writer.bytes.push(1); // MdBinaryReader.Read(bool) consumes a single byte.
  writer.variantHandle(0x3d, "type");
  writer.variantHandle(0x32, "pointer");
  writer.label("method");
  writer.unsigned(0x20);
  writer.unsigned(1);
  writer.variantHandle(0x3d, "type");
  writer.unsigned(2);
  writer.variantHandle(0x37, "array");
  writer.variantHandle(0x02, "byref");
  writer.unsigned(1);
  writer.variantHandle(0x3c, "instantiation");
  writer.label("function-pointer");
  writer.handle(0x2b, "method");
  writer.label("specification");
  writer.variantHandle(0x25, "function-pointer");
};

export const createNativeFormatSignatureFixture = () => {
  const writer = new NativeFormatFixtureWriter();
  writeReferences(writer);
  writeElementSignatures(writer);
  writeMethodSignatures(writer);
  writer.string("type-name", "Item");
  writer.string("namespace-name", "Demo");
  const handle = (name: string, type: number) => ({ type, offset: writer.labels.get(name)! });
  return { bytes: Uint8Array.from(writer.bytes), handle, labels: writer.labels };
};

export const createNativeFormatSharedSignatureFixture = () => {
  const fixture = createNativeFormatSignatureFixture();
  const offset = fixture.handle("instantiation", 0x3c).offset;
  const view = new DataView(fixture.bytes.buffer);
  // Instantiation: five-byte type handle, one-byte count, two five-byte argument handles.
  view.setUint32(offset + 7, fixture.handle("type", 0x3d).offset * 128 + 0x3d, true);
  view.setUint32(offset + 12, fixture.handle("pointer", 0x32).offset * 128 + 0x32, true);
  return fixture;
};
