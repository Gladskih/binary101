import type { DwarfCursor } from "../dwarf/cursor.js";
import type { ElfAttributeCursorAt, ElfAttributeVendor, ElfBuildAttribute } from "./attribute-types.js";

// Arm Build Attributes 64: the subsection length includes its own four bytes.
// https://github.com/ARM-software/abi-aa/blob/main/buildattr64/buildattr64.rst
export const readAarch64AttributeSubsection = async (
  cursor: DwarfCursor, cursorAt: ElfAttributeCursorAt
): Promise<ElfAttributeVendor | null> => {
  const start = cursor.position;
  const length = await cursor.uint32();
  if (length == null) return null;
  if (length < 7 || start + length > cursor.end) {
    cursor.fail("Invalid AArch64 attribute subsection length");
    return null;
  }
  const subsection = cursorAt(cursor.position, start + length);
  cursor.position = start + length;
  const name = await subsection.cstring();
  const comprehension = await subsection.uint8();
  const parameterType = await subsection.uint8();
  if (name == null || comprehension == null || parameterType == null) return null;
  const attributes = await readSubsectionAttributes(subsection, parameterType);
  if (comprehension > 1) subsection.notice(`Unknown AArch64 comprehension value ${comprehension}`);
  return { name, scopes: [], aarch64: { comprehension, parameterType, attributes } };
};

const readSubsectionAttributes = async (
  cursor: DwarfCursor, parameterType: number
): Promise<ElfBuildAttribute[]> => {
  const attributes: ElfBuildAttribute[] = [];
  if (parameterType > 1) {
    cursor.notice(`Unsupported AArch64 attribute parameter type ${parameterType}`);
    return attributes;
  }
  while (cursor.position < cursor.end) {
    const tag = await cursor.uleb();
    if (tag == null) break;
    const value = parameterType === 0 ? await cursor.uleb() : await cursor.cstring();
    if (value == null) break;
    attributes.push({ tag, value });
  }
  return attributes;
};
