import type { NativeFormatHandle } from "./native-format-reader.js";
import type { NativeFormatRecord, NativeFormatStore } from "./native-format-store.js";
import type { NativeFormatSignatures } from "./native-format-signatures.js";

export interface NativeAotConstant {
  type: string;
  value: string | number | boolean | null | NativeAotConstant[];
}
export interface NativeFormatConstantNode {
  dependencies: NativeFormatHandle[];
  format: (values: NativeAotConstant[]) => NativeAotConstant;
}

// Constant* HandleType values and payload types in the generated metadata reader.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Metadata/NativeFormat/NativeFormatReaderGen.cs
const primitiveTypes: Readonly<Record<number, string>> = {
  0x04: "bool", 0x06: "byte", 0x08: "char", 0x0a: "double", 0x0f: "short",
  0x11: "int", 0x13: "long", 0x16: "sbyte", 0x18: "float", 0x1c: "ushort", 0x1e: "uint", 0x20: "ulong"
};
const arrayElements: Readonly<Record<number, number>> = {
  0x03: 0x04, 0x05: 0x06, 0x07: 0x08, 0x09: 0x0a, 0x0e: 0x0f, 0x10: 0x11,
  0x12: 0x13, 0x15: 0x16, 0x17: 0x18, 0x1b: 0x1c, 0x1d: 0x1e, 0x1f: 0x20
};

const validateNarrow = (kind: number, value: string | number): void => {
  if ([0x08, 0x1c].includes(kind) && (Number(value) < 0 || Number(value) > 0xffff)) {
    throw new Error("NativeFormat char/UInt16 constant exceeds its storage type.");
  }
  if (kind === 0x0f && (Number(value) < -0x8000 || Number(value) > 0x7fff)) {
    throw new Error("NativeFormat Int16 constant exceeds its storage type.");
  }
};

const primitive = (kind: number, value: string | number): NativeAotConstant => {
  validateNarrow(kind, value);
  if (kind === 0x04) return { type: "bool", value: value !== 0 };
  if (kind === 0x08) return { type: "char", value: String.fromCharCode(Number(value)) };
  return { type: primitiveTypes[kind]!, value: kind === 0x16 && Number(value) >= 128 ? Number(value) - 256 : value };
};

const leaf = (value: NativeAotConstant): NativeFormatConstantNode => ({ dependencies: [], format: () => value });

const enumValue = (record: NativeFormatRecord, kind: number,
  signatures: NativeFormatSignatures, value: NativeAotConstant): NativeAotConstant => {
  if (value.type === "<invalid>") return value;
  const expected = kind === 0x0b ? ["byte[]", "sbyte[]", "short[]", "ushort[]", "int[]", "uint[]", "long[]", "ulong[]"] :
    ["byte", "sbyte", "short", "ushort", "int", "uint", "long", "ulong"];
  if (!expected.includes(value.type)) throw new Error("NativeFormat enum has a non-integral underlying constant.");
  return { type: signatures.type(record.handle(kind === 0x0b ? "elementType" : "type")) +
    (kind === 0x0b ? "[]" : ""), value: value.value };
};

const enumNode = (record: NativeFormatRecord, kind: number,
  signatures: NativeFormatSignatures): NativeFormatConstantNode => ({
  dependencies: [record.handle("value")],
  format: values => enumValue(record, kind, signatures, values[0]!)
});

const handleArrayNode = (record: NativeFormatRecord, kind: number): NativeFormatConstantNode => {
  const dependencies = record.handles("value");
  if (kind === 0x19 && dependencies.some(value => value.offset && ![0x1a, 0x14].includes(value.type))) {
    throw new Error("NativeFormat string array contains a non-string constant.");
  }
  return { dependencies, format: values => ({ type: kind === 0x19 ? "string[]" : "object[]", value: values }) };
};

const payloadNode = (record: NativeFormatRecord, kind: number,
  signatures: NativeFormatSignatures): NativeFormatConstantNode => {
  if (kind === 0x14) return leaf({ type: "object", value: null });
  if (primitiveTypes[kind]) return leaf(primitive(kind, record.values["value"] as string | number));
  const element = arrayElements[kind];
  if (element) return leaf({ type: `${primitiveTypes[element]}[]`,
    value: Array.from(record.values["value"] as ArrayLike<string | number>, value => primitive(element, value)) });
  if ([0x0b, 0x0c].includes(kind)) return enumNode(record, kind, signatures);
  if ([0x0d, 0x19].includes(kind)) return handleArrayNode(record, kind);
  throw new Error(`Unsupported NativeFormat constant kind ${kind}.`);
};

export const readNativeFormatConstantNode = (store: NativeFormatStore,
  signatures: NativeFormatSignatures, handle: NativeFormatHandle): NativeFormatConstantNode => {
  if ([0x3a, 0x3d, 0x3e].includes(handle.type)) return leaf({ type: "Type", value: signatures.type(handle) });
  if (handle.type === 0x1a) return leaf({ type: "string", value: store.reader.string(handle) });
  const record = store.record(handle);
  if (record.failure && !Array.isArray(record.values["value"])) throw record.failure;
  return payloadNode(record, handle.type, signatures);
};
