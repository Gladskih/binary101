import type { NativeAotInvokeEntry, NativeAotInvokeMap, NativeAotMetadataSection } from "./format.js";
import type { NativeAotVirtualImage } from "./virtual-image-types.js";
import { NativeFormatReader } from "./native-format-reader.js";
import { NativeHashtableReader } from "./native-hashtable.js";
import { NativeAotCodeReferences } from "./code-references.js";
import { readNativeAotSectionBytes } from "./section-bytes.js";

const readInvokeTuple = (reader: NativeFormatReader, offset: number) => {
  let position = offset;
  const next = (): number => {
    const value = reader.unsigned(position);
    position = value.nextOffset;
    return value.value;
  };
  // ReflectionInvokeMapNode.GetData and InvokeTableFlags specify this tuple and its flags.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.Compiler/Compiler/DependencyAnalysis/ReflectionInvokeMapNode.cs
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Runtime/MappingTableFlags.cs
  const flags = next();
  if (flags & ~0x70bb) throw new Error("Invoke map entry has unknown flags.");
  const metadataOffset = next();
  const declaringTypeIndex = next();
  const entrypointIndex = flags & 0x20 ? next() : null;
  const invokeStubIndex = flags & 0x80 ? null : next();
  const genericArgumentIndices: number[] = [];
  if (flags & 2) {
    const count = next();
    if (count > reader.size - position) throw new Error("Invoke generic argument count exceeds remaining bytes.");
    for (let index = 0; index < count; index += 1) genericArgumentIndices.push(next());
  }
  return { flags, metadataOffset, declaringTypeIndex, entrypointIndex, invokeStubIndex,
    genericArgumentIndices };
};

const readInvokeEntries = async (
  bytes: Uint8Array, references: NativeAotCodeReferences, issues: Set<string>
): Promise<NativeAotInvokeEntry[]> => {
  const entries: NativeAotInvokeEntry[] = [];
  const visited = new Set<number>();
  try {
    const table = new NativeHashtableReader(bytes);
    const reader = new NativeFormatReader(bytes);
    for (const record of table.entries(issues)) {
      if (visited.has(record.offset)) continue;
      visited.add(record.offset);
      try {
        const { entrypointIndex, invokeStubIndex, ...entry } = readInvokeTuple(reader, record.offset);
        entries.push({ ...entry,
          entrypointRva: entrypointIndex === null ? null : await references.resolve(entrypointIndex),
          invokeStubRva: invokeStubIndex === null ? null : await references.resolve(invokeStubIndex) });
      } catch (error) { issues.add(error instanceof Error ? error.message : "Invoke entry decoding failed."); }
    }
  } catch (error) { issues.add(error instanceof Error ? error.message : "Invoke table decoding failed."); }
  return entries;
};

export const parseNativeAotInvokeMap = async (
  image: NativeAotVirtualImage, sections: NativeAotMetadataSection[]
): Promise<NativeAotInvokeMap | undefined> => {
  const maps = sections.filter(section => section.type === 306);
  if (!maps.length) return undefined;
  const issues = new Set<string>();
  if (maps.length !== 1) return { entries: [], warnings: ["Invoke map section is ambiguous."] };
  const references = new NativeAotCodeReferences(image, sections, issues);
  const bytes = await readNativeAotSectionBytes(image, maps[0]!, issues);
  const entries = await readInvokeEntries(bytes, references, issues);
  return { entries, warnings: [...issues] };
};
