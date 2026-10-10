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
  const bytes = new Uint8Array(9);
  bytes[0] = 31;
  new DataView(bytes.buffer).setBigUint64(1, BigInt.asUintN(64, value), true);
  return [...bytes];
};

export const nativeFormatFloatBytes = (value: number, size: number): number[] => {
  const bytes = new Uint8Array(size);
  const view = new DataView(bytes.buffer);
  if (size === 4) view.setFloat32(0, value, true);
  else view.setFloat64(0, value, true);
  return [...bytes];
};

export const createNativeFormatConstantGraph = (depth: number) => {
  const writer = new NativeFormatFixtureWriter();
  for (let index = 0; index < depth; index++) {
    writer.label(`array-${index}`);
    writer.unsigned(1);
    writer.variantHandle(index === depth - 1 ? 0x11 : 0x0d, `array-${index + 1}`);
  }
  writer.label(`array-${depth}`);
  writer.unsigned(42);
  return { ...nativeFormatConstantFixture(0x0d, writer.bytes.slice(1)), handle: { type: 0x0d, offset: 4 } };
};

export const nativeFormatConstantLeaf = (value: NativeAotConstant, depth: number): NativeAotConstant => {
  let element = value;
  for (let index = 0; index < depth; index++) element = (element.value as NativeAotConstant[])[0]!;
  return element;
};
