import { NativeFormatFixtureWriter } from "./native-format-metadata-fixture.js";

type SignatureHandle = readonly [type: number, label: string];

// NativeFormat type-signature records and typed-handle tags follow the generated metadata reader.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Metadata/NativeFormat/NativeFormatReaderGen.cs
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Metadata/NativeFormat/NativeFormatReaderCommonGen.cs
const writeReferences = (writer: NativeFormatFixtureWriter): void => {
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

const writeElementSignatures = (
  writer: NativeFormatFixtureWriter, genericArguments: readonly SignatureHandle[]
): void => {
  writer.label("array");
  writer.variantHandle(0x3d, "type");
  writer.label("byref");
  writer.variantHandle(0x3f, "variable");
  writer.label("pointer");
  writer.variantHandle(0x3d, "type");
  writer.label("multi-array");
  writer.variantHandle(0x3d, "type");
  writer.unsigned(2); // Array rank 2.
  writer.unsigned(1);
  writer.unsigned(3); // One explicitly sized dimension of length 3.
  writer.unsigned(1);
  writer.bytes.push(0xfe); // One lower bound, -1 in the one-byte DecodeSigned representation.
  writer.label("instantiation");
  writer.variantHandle(0x3d, "type");
  writer.unsigned(genericArguments.length);
  genericArguments.forEach(([type, label]) => writer.variantHandle(type, label));
};

const writeMethodSignatures = (writer: NativeFormatFixtureWriter): void => {
  writer.label("modified");
  writer.bytes.push(1); // The modifier's isOptional Boolean byte selects modopt.
  writer.variantHandle(0x3d, "type");
  writer.variantHandle(0x32, "pointer");
  writer.label("method");
  writer.unsigned(0x20); // SignatureCallingConvention.HasThis.
  writer.unsigned(1); // Generic method arity.
  writer.variantHandle(0x3d, "type");
  writer.unsigned(2); // Two fixed parameters.
  writer.variantHandle(0x37, "array");
  writer.variantHandle(0x02, "byref");
  writer.unsigned(1); // One optional vararg parameter after the sentinel.
  writer.variantHandle(0x3c, "instantiation");
  writer.label("function-pointer");
  writer.handle(0x2b, "method");
  writer.label("specification");
  writer.variantHandle(0x25, "function-pointer");
};

const buildNativeFormatSignatureFixture = (genericArguments: readonly SignatureHandle[]) => {
  const writer = new NativeFormatFixtureWriter();
  writeReferences(writer);
  writeElementSignatures(writer, genericArguments);
  writeMethodSignatures(writer);
  writer.string("type-name", "Item");
  writer.string("namespace-name", "Demo");
  const handle = (name: string, type: number) => ({ type, offset: writer.labels.get(name)! });
  return { bytes: Uint8Array.from(writer.bytes), handle, labels: writer.labels };
};

export const createNativeFormatSignatureFixture = () =>
  buildNativeFormatSignatureFixture([[0x3f, "variable"], [0x2c, "method-variable"]]);

export const createNativeFormatSharedSignatureFixture = () => {
  // Both arguments are typed references to nodes already used elsewhere, forming a shared diamond.
  return buildNativeFormatSignatureFixture([[0x3d, "type"], [0x32, "pointer"]]);
};
