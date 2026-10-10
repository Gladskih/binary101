import { nativeFormatFixtureKinds as kinds, nativeFormatSampleInteger } from "./native-format-wire-fixture.js";
import { NativeFormatFixtureWriter } from "./native-format-metadata-fixture.js";
import { NativeFormatReader } from "../../analyzers/native-aot/native-format-reader.js";
import { NativeFormatStore } from "../../analyzers/native-aot/native-format-store.js";
import { NativeFormatSignatures } from "../../analyzers/native-aot/native-format-signatures.js";
import { NativeFormatConstants } from "../../analyzers/native-aot/native-format-constants.js";
import type { NativeAotConstant } from "../../analyzers/native-aot/native-format-constant-nodes.js";

export const nativeFormatConstantFixture = (kind: number, payload: number[]) => {
  const bytes = Uint8Array.of(0, ...payload);
  const warnings = new Set<string>();
  const store = new NativeFormatStore(new NativeFormatReader(bytes), warnings);
  const signatures = new NativeFormatSignatures(store);
  return { bytes, warnings, store, signatures, constants: new NativeFormatConstants(store, signatures),
    handle: { type: kind, offset: 1 } };
};

export const nativeFormatWideBytes = (value: bigint): number[] => {
  // DecodeUnsignedLong: prefix 0x1f followed by a full little-endian UInt64.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/NativeFormat/NativeFormatReader.cs
  const bytes = new Uint8Array(1 + BigUint64Array.BYTES_PER_ELEMENT);
  bytes[0] = 0x1f;
  new DataView(bytes.buffer).setBigUint64(1, BigInt.asUintN(64, value), true);
  return [...bytes];
};

export const nativeFormatFloatBytes = (value: number, size: number): number[] => {
  const bytes = new Uint8Array(size);
  const view = new DataView(bytes.buffer);
  if (size === Float32Array.BYTES_PER_ELEMENT) view.setFloat32(0, value, true);
  else view.setFloat64(0, value, true);
  return [...bytes];
};

export const createNativeFormatConstantGraph = (depth: number) => {
  const writer = new NativeFormatFixtureWriter();
  for (let index = 0; index < depth; index++) {
    writer.label(`array-${index}`);
    writer.unsigned(1);
    writer.variantHandle(index === depth - 1 ? kinds.int32 : kinds.handleArray, `array-${index + 1}`);
  }
  writer.label(`array-${depth}`);
  writer.unsigned(nativeFormatSampleInteger);
  return { ...nativeFormatConstantFixture(kinds.handleArray, writer.bytes.slice(1)),
    handle: { type: kinds.handleArray, offset: writer.labels.get("array-0")! } };
};

export const createNativeFormatSharedConstantFixture = () => {
  const writer = new NativeFormatFixtureWriter();
  writer.label("array");
  writer.unsigned(3); // Two references to one record, followed by a nil handle.
  writer.variantHandle(kinds.int32, "integer");
  writer.variantHandle(kinds.int32, "integer");
  writer.unsigned(0);
  writer.label("integer");
  writer.unsigned(nativeFormatSampleInteger);
  return { ...nativeFormatConstantFixture(kinds.handleArray, writer.bytes.slice(1)),
    handle: { type: kinds.handleArray, offset: writer.labels.get("array")! } };
};

export const createNativeFormatCyclicConstantFixture = () => {
  const writer = new NativeFormatFixtureWriter();
  writer.label("array");
  writer.unsigned(1);
  writer.variantHandle(kinds.handleArray, "array");
  return { ...nativeFormatConstantFixture(kinds.handleArray, writer.bytes.slice(1)),
    handle: { type: kinds.handleArray, offset: writer.labels.get("array")! } };
};

export const createNativeFormatDependentConstantFixture =
  (type: number, dependencyType: number, payload: number[]) => {
    const writer = new NativeFormatFixtureWriter();
    writer.label("constant");
    // String arrays have a count; EnumValue has a value handle and a type handle.
    // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Metadata/NativeFormat/NativeFormatReaderGen.cs
    if (type === kinds.stringArray) writer.unsigned(1);
    writer.variantHandle(dependencyType, "value");
    if (type === kinds.enum) writer.unsigned(0); // Nil enum type in these malformed fixtures.
    writer.label("value");
    writer.bytes.push(...payload);
    return { ...nativeFormatConstantFixture(type, writer.bytes.slice(1)),
      handle: { type, offset: writer.labels.get("constant")! } };
  };

export const nativeFormatConstantLeaf = (value: NativeAotConstant, depth: number): NativeAotConstant => {
  let element = value;
  for (let index = 0; index < depth; index++) element = (element.value as NativeAotConstant[])[0]!;
  return element;
};
