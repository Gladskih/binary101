import type { FileRangeReader } from "../file-range-reader.js";
import type { ElfVersionDefinition, ElfVersionRequirement } from "./version-types.js";
import { createVersionStringReader, readVersionBytes } from "./version-reader.js";
import type { ElfVersionTable } from "./version-reader.js";

// Fixed record sizes/offsets: LSB 10.7.3 and 10.7.4; identical for ELF32/64.
// https://refspecs.linuxfoundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/symversion.html
async function* versionChain(
  reader: FileRangeReader, table: ElfVersionTable, start: number, count: number,
  size: number, little: boolean, issues: string[]
): AsyncGenerator<{ view: DataView; offset: number }> {
  let offset = start;
  // Resource policy: bound result memory for maliciously large tables.
  const limit = Math.min(count, 100000);
  if (limit !== count) issues.push("Version records exceed the 100000 record limit.");
  for (let index = 0; index < limit; index += 1) {
    const view = await readVersionBytes(reader, table, offset, size, issues);
    if (!view) return;
    yield { view, offset };
    const next = view.getUint32(size - 4, little);
    if (index + 1 === count) {
      if (next) issues.push("Version chain continues beyond its declared count.");
      return;
    }
    if (next < size) {
      issues.push("Version chain ends early or overlaps its preceding record.");
      return;
    }
    offset += next;
  }
}

const auxiliaryOffset = (
  view: DataView, offset: number, little: boolean, issues: string[]
): number | null => {
  const relative = view.getUint32(view.byteLength - 8, little);
  if (relative >= view.byteLength) return offset + relative;
  issues.push("Version auxiliary offset overlaps its parent record.");
  return null;
};

export const readElfVersionDefinitions = async (
  reader: FileRangeReader, table: ElfVersionTable, little: boolean, issues: string[]
): Promise<ElfVersionDefinition[]> => {
  const definitions: ElfVersionDefinition[] = [];
  const readString = createVersionStringReader(reader, table, issues);
  for await (const { view, offset } of versionChain(reader, table, 0, table.count, 20, little, issues)) {
    if (view.getUint16(0, little) !== 1) {
      issues.push("Unsupported version definition revision.");
      continue;
    }
    const names: string[] = [];
    const auxiliary = auxiliaryOffset(view, offset, little, issues);
    const count = view.getUint16(6, little);
    if (!count) issues.push("Version definition has no auxiliary name.");
    if (auxiliary != null) {
      for await (const item of versionChain(reader, table, auxiliary, count, 8, little, issues)) {
        names.push(await readString(item.view.getUint32(0, little)));
      }
    }
    definitions.push({ index: view.getUint16(4, little), flags: view.getUint16(2, little),
      hash: view.getUint32(8, little), names });
  }
  return definitions;
};

export const readElfVersionRequirements = async (
  reader: FileRangeReader, table: ElfVersionTable, little: boolean, issues: string[]
): Promise<ElfVersionRequirement[]> => {
  const requirements: ElfVersionRequirement[] = [];
  const readString = createVersionStringReader(reader, table, issues);
  for await (const { view, offset } of versionChain(reader, table, 0, table.count, 16, little, issues)) {
    if (view.getUint16(0, little) !== 1) {
      issues.push("Unsupported version requirement revision.");
      continue;
    }
    const versions: ElfVersionRequirement["versions"] = [];
    const auxiliary = auxiliaryOffset(view, offset, little, issues);
    if (auxiliary != null) {
      for await (const item of versionChain(reader, table, auxiliary,
        view.getUint16(2, little), 16, little, issues)) {
        versions.push({ hash: item.view.getUint32(0, little),
          flags: item.view.getUint16(4, little), index: item.view.getUint16(6, little),
          name: await readString(item.view.getUint32(8, little)) });
      }
    }
    requirements.push({ file: await readString(view.getUint32(4, little)), versions });
  }
  return requirements;
};
