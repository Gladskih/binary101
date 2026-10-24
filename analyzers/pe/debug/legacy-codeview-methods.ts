import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";

export interface LegacyCodeViewMethod {
  attributes: number;
  typeIndex: number;
  vtableOffset?: number;
}

// mlMethod[_16t]: wide entries add a reserved uint16 before the type index.
// Introducing virtual / pure introducing virtual entries append VFTableOffset.
// https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h
// LLVM MapOneMethodRecord uses a signed VFTableOffset.
// https://github.com/llvm/llvm-project/blob/llvmorg-23.1.3/llvm/lib/DebugInfo/CodeView/TypeRecordMapping.cpp
const readMethod = async (reader: LegacyCodeViewReader, offset: number, width: 2 | 4) => {
  const view = await reader.view(offset, width * 2);
  const attributes = view.getUint16(0, true);
  const property = attributes >>> 2 & 7;
  if (attributes & ~0x3ff) reader.warn("CodeView method has unknown attribute bits.");
  if (property === 7) reader.warn("CodeView method has a reserved method property.");
  if (width === 4 && view.getUint16(2, true)) reader.warn("CodeView method reserved padding is nonzero.");
  const method: LegacyCodeViewMethod = { attributes,
    typeIndex: width === 2 ? view.getUint16(2, true) : view.getUint32(4, true) };
  const end = offset + width * 2;
  if (property !== 4 && property !== 6) return { method, end };
  method.vtableOffset = (await reader.view(end, 4)).getInt32(0, true);
  return { method, end: end + 4 };
};

const readPadding = async (reader: LegacyCodeViewReader, offset: number, marker: number): Promise<void> => {
  const count = marker & 15;
  if (!count) throw new Error("CodeView method-list LF_PAD0 cannot advance.");
  await reader.view(offset, count);
  if (offset + count !== reader.size) reader.warn("CodeView method list has bytes after padding; they were not decoded.");
};

/** Retain recovered methods and diagnose truncated entries without throwing to the caller. */
export const readLegacyCodeViewMethods = async (
  reader: LegacyCodeViewReader, width: 2 | 4
): Promise<LegacyCodeViewMethod[]> => {
  const methods: LegacyCodeViewMethod[] = [];
  let offset = 0;
  while (offset < reader.size) {
    try {
      const marker = (await reader.view(offset, 1)).getUint8(0);
      // CodeViewRecordIO::mapVectorTail terminates at the first LF_PAD marker.
      if (marker >= 0xf0) { await readPadding(reader, offset, marker); break; }
      const next = await readMethod(reader, offset, width);
      methods.push(next.method);
      offset = next.end;
    } catch (error) { reader.warn(`CodeView method list: ${String(error)}`); break; }
  }
  return methods;
};
