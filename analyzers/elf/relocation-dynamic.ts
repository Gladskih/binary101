import type { FileRangeReader } from "../file-range-reader.js";
import type { ElfRelocationImage } from "./relocation-types.js";
import { readElfDynamicEntries, type ElfDynamicEntry } from "./dynamic-entries.js";
import { selectElfBinaryLayout } from "./binary-layout.js";
import { ELF_DYNAMIC_TAG } from "./abi-constants.js";

const relocationTags = new Set<number>(Object.values(ELF_DYNAMIC_TAG));

// gABI Dynamic section, including DT_REL*, DT_RELA*, DT_RELR* and DT_JMPREL.
// https://gabi.xinuos.com/elf/08-dynamic.html#dynamic-section
export const readElfRelocationTags = async (
  reader: FileRangeReader, elf: ElfRelocationImage, issues: string[],
  parsedEntries?: ElfDynamicEntry[], layout = selectElfBinaryLayout(elf)
): Promise<Map<number, bigint>> => {
  const entries = parsedEntries ?? await readElfDynamicEntries(reader, elf, issues, layout);
  const tags = new Map<number, bigint>();
  const conflicts = new Set<number>();
  for (const { tag, value } of entries) {
    // Only single-valued tags consumed by this analysis; DT_NEEDED may repeat.
    if (!relocationTags.has(tag)) continue;
    if (tags.has(tag) && tags.get(tag) !== value) {
      issues.push(`Conflicting ELF dynamic relocation tag ${tag}.`);
      conflicts.add(tag);
    }
    if (conflicts.has(tag)) tags.delete(tag);
    else tags.set(tag, value);
  }
  return tags;
};
