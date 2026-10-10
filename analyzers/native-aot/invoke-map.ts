import type { NativeAotInvokeEntry, NativeAotInvokeMap, NativeAotMetadataSection } from "./format.js";
import type { NativeAotVirtualImage } from "./virtual-image-types.js";
import { NativeFormatReader, type NativeFormatLayout } from "./native-format-reader.js";
import { NativeFormatCursor } from "./native-format-cursor.js";
import { readNativeAotInvokeTuple } from "./invoke-tuple.js";
import { NativeHashtableReader } from "./native-hashtable.js";
import { NativeAotCodeReferences } from "./code-references.js";
import { readNativeAotSectionBytes } from "./section-bytes.js";

const readInvokeEntries = async (
  bytes: Uint8Array, references: NativeAotCodeReferences, issues: Set<string>, layout: NativeFormatLayout
): Promise<NativeAotInvokeEntry[]> => {
  const entries: NativeAotInvokeEntry[] = [];
  const visited = new Set<number>();
  try {
    const table = new NativeHashtableReader(bytes);
    const reader = new NativeFormatReader(bytes, layout);
    for (const record of table.entries(issues)) {
      if (visited.has(record.offset)) continue;
      visited.add(record.offset);
      try {
        const { entrypointIndex, invokeStubIndex, ...entry } =
          readNativeAotInvokeTuple(new NativeFormatCursor(reader, record.offset));
        entries.push({ ...entry,
          entrypointRva: entrypointIndex === null ? null : await references.resolve(entrypointIndex),
          invokeStubRva: invokeStubIndex === null ? null : await references.resolve(invokeStubIndex) });
      } catch (error) { issues.add(error instanceof Error ? error.message : "Invoke entry decoding failed."); }
    }
  } catch (error) { issues.add(error instanceof Error ? error.message : "Invoke table decoding failed."); }
  return entries;
};

export const parseNativeAotInvokeMap = async (
  image: NativeAotVirtualImage, sections: NativeAotMetadataSection[], layout: NativeFormatLayout = "dotnet10"
): Promise<NativeAotInvokeMap | undefined> => {
  const maps = sections.filter(section => section.type === 306);
  if (!maps.length) return undefined;
  const issues = new Set<string>();
  if (maps.length !== 1) return { entries: [], warnings: ["Invoke map section is ambiguous."] };
  const references = new NativeAotCodeReferences(image, sections, issues);
  const bytes = await readNativeAotSectionBytes(image, maps[0]!, issues);
  const entries = await readInvokeEntries(bytes, references, issues, layout);
  return { entries, warnings: [...issues] };
};
