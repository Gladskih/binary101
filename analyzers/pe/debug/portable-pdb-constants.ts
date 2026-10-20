import { decodeMetadataUtf16 } from "../clr/metadata-utf16.js";
import { PortablePdbBlobReader } from "./portable-pdb-blob.js";

export interface PortablePdbTypeReference { tableId: number; row: number; }
export type PortablePdbConstant = {
  typeCode: number;
  typeReference?: PortablePdbTypeReference;
  modifiers?: { required: boolean; typeReference: PortablePdbTypeReference }[];
} & ({ value: string | number | boolean | null; data?: never } | { data: number[]; value?: never });

// LocalConstantSig and ECMA-335 II.23.1.16 element type codes.
// https://github.com/dotnet/runtime/blob/main/docs/design/specs/PortablePdb-Metadata.md#localconstantsig-blob
const PRIMITIVES: Readonly<Record<number, {
  size: number; read: (view: DataView) => string | number | boolean;
}>> = {
  2: { size: 1, read: view => {
    if (view.getUint8(0) > 1) throw new Error("Boolean value is neither zero nor one");
    return view.getUint8(0) === 1;
  } },
  3: { size: 2, read: view => String.fromCharCode(view.getUint16(0, true)) },
  4: { size: 1, read: view => view.getInt8(0) },
  5: { size: 1, read: view => view.getUint8(0) },
  6: { size: 2, read: view => view.getInt16(0, true) },
  7: { size: 2, read: view => view.getUint16(0, true) },
  8: { size: 4, read: view => view.getInt32(0, true) },
  9: { size: 4, read: view => view.getUint32(0, true) },
  10: { size: 8, read: view => view.getBigInt64(0, true).toString() },
  11: { size: 8, read: view => view.getBigUint64(0, true).toString() },
  12: { size: 4, read: view => view.getFloat32(0, true) },
  13: { size: 8, read: view => view.getFloat64(0, true) }
};

const typeReference = (
  reader: PortablePdbBlobReader, counts: ReadonlyMap<number, number>
): PortablePdbTypeReference => {
  const value = reader.compressed();
  const tableId = [2, 1, 0x1b][value & 3] ?? -1;
  const row = value >>> 2;
  if (!row || row > (counts.get(tableId) ?? 0)) throw new Error("type reference is out of range");
  return { tableId, row };
};

const constantString = (reader: PortablePdbBlobReader): string | null => {
  if (reader.remaining === 1 && reader.bytes[reader.offset] === 255) { reader.byte(); return null; }
  if (reader.remaining % 2) throw new Error("constant string has a partial UTF-16 code unit");
  return decodeMetadataUtf16(reader.take(reader.remaining), [], "Portable PDB constant");
};

const constantValue = (
  typeCode: number, reader: PortablePdbBlobReader, counts: ReadonlyMap<number, number>
): PortablePdbConstant => {
  if (typeCode === 0x0e) return { typeCode, value: constantString(reader) };
  if (typeCode === 0x1c) return { typeCode, value: null };
  if (typeCode === 0x11 || typeCode === 0x12) {
    return { typeCode, typeReference: typeReference(reader, counts), data: [...reader.take(reader.remaining)] };
  }
  const primitive = PRIMITIVES[typeCode];
  if (!primitive) throw new Error(`unsupported constant type ${typeCode}`);
  const bytes = reader.take(primitive.size);
  const value = primitive.read(new DataView(bytes.buffer, bytes.byteOffset, bytes.length));
  return { typeCode, value, ...(reader.remaining && typeCode <= 0x0b
    ? { typeReference: typeReference(reader, counts) } : {}) };
};

export const decodePortablePdbConstant = (
  bytes: Uint8Array | null, counts: ReadonlyMap<number, number>, issues: string[]
): PortablePdbConstant | null => {
  if (!bytes) return null;
  const reader = new PortablePdbBlobReader(bytes);
  try {
    const modifiers: NonNullable<PortablePdbConstant["modifiers"]> = [];
    while (reader.bytes[reader.offset] === 0x1f || reader.bytes[reader.offset] === 0x20) {
      const required = reader.byte() === 0x1f;
      modifiers.push({ required, typeReference: typeReference(reader, counts) });
    }
    const result = constantValue(reader.byte(), reader, counts);
    reader.finish();
    return { ...result, ...(modifiers.length ? { modifiers } : {}) };
  } catch (error) {
    issues.push(`Portable PDB local constant: ${(error as Error).message}.`);
    return null;
  }
};
