import type { FileRangeReader } from "../../file-range-reader.js";
import type { RvaToOffset } from "../types.js";
import { createRvaRangeReader } from "../rva-range-reader.js";
import { parseIa64Descriptors, type Ia64DescriptorStatistics } from "./ia64-descriptors.js";

export interface Ia64UnwindInfo extends Ia64DescriptorStatistics {
  version?: number;
  flags?: number;
}

// Windows uses USHORT Version, USHORT Flags, ULONG DataLength, unlike ELF's
// ordering. DataLength counts 8-byte words; the descriptor language follows Intel.
// Microsoft engineer's header dump and personality-location calculation:
// https://groups.google.com/g/microsoft.public.windbg/c/iX3KQeqe3_E
export const parseIa64UnwindInfo = async (reader: FileRangeReader, rvaToOff: RvaToOffset,
  reference: number): Promise<Ia64UnwindInfo> => {
  const issues: string[] = [];
  const header = await createRvaRangeReader(reader, rvaToOff, reference, 8).read(0, 8);
  if (header.byteLength < 8) return { counts: {}, issues: ["IA64 unwind header is unmapped or truncated."] };
  if (reference % 8) issues.push("IA64 unwind information is not 8-byte aligned.");
  const version = header.getUint16(0, true);
  const flags = header.getUint16(2, true);
  if (version !== 3) return { version, flags, counts: {},
    issues: [...issues, `IA64 unwind version ${version} is not decoded.`] };
  if (flags & ~3) issues.push("IA64 unwind header contains unknown flag bits.");
  const length = header.getUint32(4, true) * 8;
  const source = createRvaRangeReader(reader, rvaToOff, reference + 8, length);
  if (source.size < length) issues.push("IA64 unwind descriptor area is truncated.");
  const statistics = await parseIa64Descriptors(source);
  return { ...statistics, version, flags, issues: [...issues, ...statistics.issues] };
};
