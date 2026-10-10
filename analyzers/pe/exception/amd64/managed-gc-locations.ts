import type { FileRangeReader } from "../../../file-range-reader.js";
import { readMappedRvaPrefix } from "../../rva-byte-reader.js";
import type { RvaToOffset } from "../../types.js";

const header = async (reader: FileRangeReader, mapper: RvaToOffset, rva: number): Promise<DataView> => {
  const view = await readMappedRvaPrefix(reader, rva, 4, mapper);
  if (view.byteLength !== 4) throw new Error("Managed unwind header is truncated.");
  if ((view.getUint8(0) & 7) !== 1 && (view.getUint8(0) & 7) !== 2) {
    throw new Error("Managed unwind header has an unsupported version.");
  }
  if ((view.getUint8(0) >>> 3) & ~3) throw new Error("Managed unwind header has chained or reserved flags.");
  return view;
};

// R2R's AMD64 unwind blob always reserves a personality DWORD after aligned codes.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.Reflection.ReadyToRun/Amd64/UnwindInfo.cs
export const locateReadyToRunGcInfo = async (reader: FileRangeReader, mapper: RvaToOffset,
  unwindRva: number): Promise<number> => {
  const size = Math.ceil((4 + (await header(reader, mapper, unwindRva)).getUint8(2) * 2) / 4) * 4 + 4;
  if ((await readMappedRvaPrefix(reader, unwindRva, size, mapper)).byteLength !== size) {
    throw new Error("ReadyToRun unwind codes or personality are truncated.");
  }
  return unwindRva + size;
};

// NativeAOT places its own flags byte after the OS unwind blob, followed by optional
// associated-data/EH relative pointers. Funclet blobs refer to a root method's GC map.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/nativeaot/Runtime/windows/CoffNativeCodeManager.cpp
export const locateNativeAotGcInfo = async (reader: FileRangeReader, mapper: RvaToOffset,
  unwindRva: number): Promise<number | null> => {
  const view = await header(reader, mapper, unwindRva);
  const codesEnd = 4 + view.getUint8(2) * 2;
  const tailRva = unwindRva + ((view.getUint8(0) >>> 3) & 3
    ? Math.ceil(codesEnd / 4) * 4 + 4 : codesEnd);
  const tail = await readMappedRvaPrefix(reader, tailRva, 1, mapper);
  if (tail.byteLength !== 1) throw new Error("NativeAOT unwind flags are truncated.");
  if ((await readMappedRvaPrefix(reader, unwindRva, tailRva - unwindRva, mapper)).byteLength !==
    tailRva - unwindRva) throw new Error("NativeAOT unwind codes or personality are truncated.");
  const flags = tail.getUint8(0);
  if ((flags & 0xe0) || (flags & 3) === 3) throw new Error("NativeAOT unwind flags are reserved.");
  if (flags & 3) return null;
  const size = 1 + Number(!!(flags & 0x10)) * 4 + Number(!!(flags & 4)) * 4;
  if ((await readMappedRvaPrefix(reader, tailRva, size, mapper)).byteLength !== size) {
    throw new Error("NativeAOT unwind optional pointers are truncated.");
  }
  return tailRva + size;
};
