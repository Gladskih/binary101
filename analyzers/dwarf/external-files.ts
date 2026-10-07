import { dwarfAttributeValue, dwarfNumericValue, dwarfStringValue } from "./attribute-values.js";
import { readDwarfAlternateFile, readDwarfSupplementaryFile } from "./supplementary.js";
import type { DwarfSectionSource, DwarfUnit } from "./types.js";

export const dwarfSplitIdentity = (unit: DwarfUnit): bigint | null =>
  unit.dwoId ?? dwarfNumericValue(dwarfAttributeValue(unit.dies[0], 0x2131)); // GNU_dwo_id.

export const dwarfSplitFilename = (unit: DwarfUnit): string | null =>
  dwarfStringValue(dwarfAttributeValue(unit.dies[0], 0x76) ??
    dwarfAttributeValue(unit.dies[0], 0x2130)); // DW_AT_dwo_name / GNU_dwo_name.

export const validateDwarfSplitFiles = (units: DwarfUnit[], issues: string[]): void => {
  const splitIds = new Set<bigint | null>(units.filter(unit => unit.sectionName.endsWith(".dwo"))
    .map(dwarfSplitIdentity).filter(id => id != null));
  for (const unit of units) {
    if (unit.sectionName.endsWith(".dwo")) continue;
    const filename = dwarfSplitFilename(unit);
    if (filename && !splitIds.has(dwarfSplitIdentity(unit))) {
      issues.push(`Split DWARF file ${filename} is required for the full compilation unit; it is not present in this file.`);
    }
  }
};

export const readDwarfExternalFiles = async (sections: Map<string, DwarfSectionSource>,
  byteOrder: "little" | "big", issues: string[]) => {
  const supplementary = sections.get(".debug_sup");
  const alternate = sections.get(".gnu_debugaltlink");
  const supplementaryFile = supplementary
    ? await readDwarfSupplementaryFile(supplementary, byteOrder, issues) : null;
  const alternateFile = alternate ? await readDwarfAlternateFile(alternate, issues) : null;
  return { ...(supplementaryFile ? { supplementaryFile } : {}),
    ...(alternateFile ? { alternateFile } : {}) };
};
