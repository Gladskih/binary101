import type { NativeAotMetadataSection, NativeAotStackTraceMap, NativeAotStackTraceMethod } from "./format.js";
import type { NativeAotVirtualImage } from "./virtual-image-types.js";
import { NativeFormatReader } from "./native-format-reader.js";
import { readNativeAotSectionBytes } from "./section-bytes.js";

// StackTraceMethodMappingNode emits a DWORD count followed by command/context/RELPTR32 rows.
// StackTraceDataCommand and StackTraceMetadata.PopulateRvaToTokenMap define field ordering.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Runtime/StackTraceData.cs
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.Compiler/Compiler/DependencyAnalysis/StackTraceMethodMappingNode.cs
const readRow = (reader: NativeFormatReader, offset: number, sectionRva: number) => {
  let position = offset;
  const unsigned = (): number => {
    const field = reader.unsigned(position);
    position = field.nextOffset;
    return field.value;
  };
  const command = reader.uint8(position++).value;
  if (command & ~0x1f) throw new Error("Stack-trace row has unknown command flags.");
  const entry: NativeAotStackTraceMethod = { command, methodRva: null };
  if (command & 1) { entry.owningTypeToken = reader.uint32(position); position += 4; }
  if (command & 2) entry.nameOffset = unsigned();
  if (command & 4) entry.signatureOffset = unsigned();
  if (command & 8) entry.genericSignature = {
    signatureOffset: unsigned(), argumentCollectionOffset: unsigned()
  };
  entry.methodRva = sectionRva + position + (reader.uint32(position) >> 0);
  return { entry, nextOffset: position + 4 };
};

const readRows = (
  bytes: Uint8Array, sectionRva: number, image: NativeAotVirtualImage, issues: Set<string>
): NativeAotStackTraceMethod[] => {
  const entries: NativeAotStackTraceMethod[] = [];
  try {
    const reader = new NativeFormatReader(bytes);
    const count = reader.uint32(0);
    // Every row requires at least a command byte and a fixed-width relative pointer.
    const available = Math.min(count, Math.floor((reader.size - 4) / 5));
    if (available < count) issues.add("Stack-trace method table is truncated.");
    let position = 4;
    for (let index = 0; index < available; index += 1) {
      const row = readRow(reader, position, sectionRva);
      position = row.nextOffset;
      if (!Number.isSafeInteger(row.entry.methodRva) || !image.isExecutableAddress(row.entry.methodRva!)) {
        row.entry.methodRva = null;
        issues.add("Stack-trace method target is not file-backed executable code.");
      }
      entries.push(row.entry);
    }
    if (position < bytes.length) issues.add("Stack-trace method table has trailing or incomplete data.");
  } catch (error) { issues.add(error instanceof Error ? error.message : "Stack-trace table decoding failed."); }
  return entries;
};

export const parseNativeAotStackTraceMap = async (
  image: NativeAotVirtualImage, sections: NativeAotMetadataSection[]
): Promise<NativeAotStackTraceMap | undefined> => {
  const maps = sections.filter(section => section.type === 327);
  if (!maps.length) return undefined;
  if (maps.length !== 1) return { entries: [], warnings: ["Stack-trace method map section is ambiguous."] };
  const issues = new Set<string>();
  const bytes = await readNativeAotSectionBytes(image, maps[0]!, issues);
  return { entries: readRows(bytes, maps[0]!.rva, image, issues), warnings: [...issues] };
};
