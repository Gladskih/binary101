import type { FileRangeReader } from "../file-range-reader.js";
import type { ElfParseResult } from "./types.js";
import type { ElfUnwindFde } from "./unwind-types.js";
import { elfVirtualRange } from "./relocation-reader.js";

const directFrame = (frame: ElfUnwindFde): boolean =>
  !!frame.lsda && !frame.lsda.indirect && !!frame.start && !frame.start.indirect;

const funcletLink = (view: DataView, address: bigint) => {
  if (view.byteLength !== 9) return null;
  const kind = view.getUint8(0) & 3;
  if ((view.getUint8(0) & 0xe0) || (kind !== 1 && kind !== 2)) return null;
  return { rootLsda: address + 1n + BigInt(view.getInt32(1, true)), codeOffset: view.getInt32(5, true) };
};

// UnixNativeCodeManager::FindMethodInfo: a funclet carries a relative root-LSDA
// pointer and an offset back to the root's native start. Validate both identities.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/nativeaot/Runtime/unix/UnixNativeCodeManager.cpp
export const identifyNativeAotGcFunclets = async (reader: FileRangeReader, elf: ElfParseResult,
  roots: ElfUnwindFde[], nativeLsdas: Set<bigint>): Promise<void> => {
  const identities = new Map(roots.flatMap(frame => frame.lsda && !frame.lsda.indirect
    ? [[frame.lsda.address, frame.start!.address] as const] : []));
  for (const frame of (elf.unwind ?? []).flatMap(section => section.fdes)) {
    if (!directFrame(frame) || nativeLsdas.has(frame.lsda!.address)) continue;
    const range = elfVirtualRange(elf.programHeaders, frame.lsda!.address, 9n, reader.size);
    if (!range) continue;
    const link = funcletLink(await reader.read(range.offset, range.size), frame.lsda!.address);
    if (link && identities.get(link.rootLsda) === frame.start!.address - BigInt(link.codeOffset)) {
      nativeLsdas.add(frame.lsda!.address);
    }
  }
};
