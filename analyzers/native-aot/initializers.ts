import {
  NATIVE_AOT_EAGER_CCTOR_SECTION,
  NATIVE_AOT_MODULE_INITIALIZER_LIST_SECTION,
  type NativeAotMetadata,
  type NativeAotMetadataSection,
  type NativeAotInitializerTable
} from "./format.js";
import type { NativeAotVirtualImage } from "./virtual-image-types.js";

// RunInitializers consumes signed, slot-relative int32 pointers for both section IDs.
// TargetDetails.SupportsRelativePointers is true on all supported PE/ELF x86 targets.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/nativeaot/Common/src/Internal/Runtime/CompilerHelpers/StartupCodeHelpers.cs
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/TypeSystem/Common/TargetDetails.cs
const ENTRY_SIZE = 4;
// Resource policy: bounded reads through the container's range reader.
const CHUNK_BYTES = 4096;

const readInitializerTargets = async (
  image: NativeAotVirtualImage,
  rva: number,
  size: number
): Promise<number[] | string> => {
  const targets = new Set<number>();
  for (let offset = 0; offset < size; offset += CHUNK_BYTES) {
    const length = Math.min(CHUNK_BYTES, size - offset);
    const view = await image.readData(rva + offset, length, ENTRY_SIZE);
    if (!view || view.byteLength !== length) return "Initializer table is truncated or unreadable.";
    for (let index = 0; index < length; index += ENTRY_SIZE) {
      const target = rva + offset + index + view.getInt32(index, true);
      if (!image.isExecutableAddress(target)) {
        return "Initializer target does not map to file-backed executable code.";
      }
      targets.add(target);
    }
  }
  return [...targets];
};

const parseInitializerTable = async (
  image: NativeAotVirtualImage,
  section: NativeAotMetadataSection
): Promise<number[] | string> => {
  const { rva, size } = section;
  // Resource policy, not a format constraint: at most 1 MiB (262144 entries) per table.
  if (size == null || !Number.isSafeInteger(size) || size < 0 ||
    size > 1024 * 1024 || size % ENTRY_SIZE !== 0) {
    return "Initializer table has an unknown, invalid, or excessive byte size.";
  }
  if (size === 0) return [];
  if (!image.isDataRange(rva, size, ENTRY_SIZE)) {
    return "Initializer table is not aligned, fully file-backed data.";
  }
  try {
    return await readInitializerTargets(image, rva, size);
  } catch {
    return "Initializer table could not be read.";
  }
};

// Exact released versions checked in ModuleHeaders.cs, RunInitializers and TargetDetails.cs.
// .NET 8 also allowed CppCodegen absolute pointers with no distinguishing header flag.
// https://github.com/dotnet/runtime/blob/v9.0.0/src/coreclr/tools/Common/Internal/Runtime/ModuleHeaders.cs
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Runtime/ModuleHeaders.cs
const isKnownInitializerVersion = (major: number, minor: number): boolean =>
  (major === 10 && minor === 1) || (major === 16 && minor === 0);

export const parseNativeAotInitializers = async (
  image: NativeAotVirtualImage,
  header: Pick<NativeAotMetadata, "majorVersion" | "minorVersion" | "sections">
): Promise<NativeAotInitializerTable[]> => {
  const tables: NativeAotInitializerTable[] = [];
  for (const section of header.sections) {
    if (section.type !== NATIVE_AOT_EAGER_CCTOR_SECTION &&
      section.type !== NATIVE_AOT_MODULE_INITIALIZER_LIST_SECTION) continue;
    const result = isKnownInitializerVersion(header.majorVersion, header.minorVersion)
      ? await parseInitializerTable(image, section)
      : "Initializer encoding is not verified for this NativeAOT header version.";
    tables.push({
      sectionType: section.type,
      targetRvas: typeof result === "string" ? [] : result,
      warnings: typeof result === "string" ? [result] : []
    });
  }
  return tables;
};
