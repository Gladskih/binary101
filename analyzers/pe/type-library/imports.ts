import type { TypeLibraryReader } from "./reader.js";
import type { TypeLibraryImport, TypeLibraryImportedType } from "./types.js";

// MSFT_ReadAllRefs and import library loop in Wine ITypeLib2_Constructor_MSFT.
// https://github.com/wine-mirror/wine/blob/master/dlls/oleaut32/typelib.c
export const readImports = (reader: TypeLibraryReader): TypeLibraryImport[] => {
  const result: TypeLibraryImport[] = [];
  const segment = reader.segment("ImpFiles");
  if (!segment) return result;
  for (let offset = 0; offset < segment.length;) {
    const start = reader.at("ImpFiles", offset, 14);
    if (start === null) break;
    const length = reader.view.getUint16(start + 12, true) >>> 2;
    const size = Math.ceil((14 + length) / 4) * 4;
    if (reader.at("ImpFiles", offset, size) === null) break;
    result.push({
      offset,
      name: reader.text(start + 14, length),
      guid: reader.lookup(reader.guids, reader.view.getInt32(start, true), "GUID"),
      lcid: reader.view.getUint32(start + 4, true),
      version: reader.view.getUint32(start + 8, true)
    });
    offset += size;
  }
  return result;
};

export const readImportedTypes = (reader: TypeLibraryReader): TypeLibraryImportedType[] => {
  const result: TypeLibraryImportedType[] = [];
  const segment = reader.segment("ImpInfo");
  if (!segment) return result;
  if (segment.length % 12) reader.warn("TYPELIB imported type table is truncated.");
  for (let offset = 0; offset + 12 <= segment.length; offset += 12) {
    const start = segment.offset + offset;
    const flags = reader.view.getUint32(start, true);
    const identifier = reader.view.getInt32(start + 8, true);
    result.push({ offset, flags, libraryOffset: reader.view.getInt32(start + 4, true),
      identifier: flags & 0x10000 ? reader.lookup(reader.guids, identifier, "GUID") : identifier });
  }
  return result;
};
