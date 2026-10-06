import { NativeFormatCursor } from "./native-format-cursor.js";
import { NativeFormatReader } from "./native-format-reader.js";
import { NativeHashtableReader } from "./native-hashtable.js";

export const readNativeAotHashEntries = async <TEntry>(
  bytes: Uint8Array, decode: (cursor: NativeFormatCursor) => Promise<TEntry>,
  issues: Set<string>
): Promise<TEntry[]> => {
  const entries: TEntry[] = [];
  const visited = new Set<number>();
  try {
    const reader = new NativeFormatReader(bytes);
    for (const record of new NativeHashtableReader(bytes).entries(issues)) {
      if (visited.has(record.offset)) continue;
      visited.add(record.offset);
      try { entries.push(await decode(new NativeFormatCursor(reader, record.offset))); }
      catch (error) { issues.add(error instanceof Error ? error.message : "NativeAOT hash entry decoding failed."); }
    }
  } catch (error) { issues.add(error instanceof Error ? error.message : "NativeAOT hash table decoding failed."); }
  return entries;
};
