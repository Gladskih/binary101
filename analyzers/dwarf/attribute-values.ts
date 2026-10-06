import type { DwarfDie, DwarfFormValue, DwarfUnit, DwarfUnitRoot } from "./types.js";
import { DWARF_ATTRIBUTE } from "./constants.js";

export const dwarfAttributeValue = (
  die: DwarfDie | undefined,
  name: number
): DwarfFormValue | undefined => die?.attributes.find(item => item.name === name)?.value;

export const dwarfNumericValue = (value: DwarfFormValue | undefined): bigint | null =>
  value?.kind === "unsigned" || value?.kind === "signed" ? value.value : null;

export const dwarfStringValue = (value: DwarfFormValue | undefined): string | null =>
  value?.kind === "string" ? value.value : null;

// A view for consumers of unit metadata; parsed units retain only canonical DIEs.
const rootLanguage = (root: DwarfDie): number | null => {
  const language = dwarfNumericValue(dwarfAttributeValue(root, DWARF_ATTRIBUTE.language));
  return language == null || language < 0n || language > BigInt(Number.MAX_SAFE_INTEGER)
    ? null : Number(language);
};

export const dwarfUnitRoot = (unit: DwarfUnit | undefined): DwarfUnitRoot | null => {
  const root = unit?.dies[0];
  if (!root) return null;
  const name = dwarfStringValue(dwarfAttributeValue(root, DWARF_ATTRIBUTE.name));
  const producer = dwarfStringValue(dwarfAttributeValue(root, DWARF_ATTRIBUTE.producer));
  const compilationDirectory = dwarfStringValue(
    dwarfAttributeValue(root, DWARF_ATTRIBUTE.compilationDirectory)
  );
  const language = rootLanguage(root);
  const statementListOffset = dwarfNumericValue(
    dwarfAttributeValue(root, DWARF_ATTRIBUTE.statementList)
  );
  return {
    tag: root.tag,
    ...(name == null ? {} : { name }),
    ...(producer == null ? {} : { producer }),
    ...(compilationDirectory == null ? {} : { compilationDirectory }),
    ...(language == null ? {} : { language }),
    ...(statementListOffset == null || statementListOffset < 0n ? {} : { statementListOffset })
  };
};
