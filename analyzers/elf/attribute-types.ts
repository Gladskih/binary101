import type { DwarfCursor } from "../dwarf/cursor.js";

export interface ElfBuildAttribute {
  tag: bigint;
  value: bigint | string | { flag: bigint; vendor: string };
}
export interface ElfAttributeScope { tag: bigint; indices: bigint[]; attributes: ElfBuildAttribute[] }
export interface ElfAttributeVendor { name: string; scopes: ElfAttributeScope[] }
export interface ElfAttributeSection {
  sectionIndex: number;
  vendors: ElfAttributeVendor[];
  issues: string[];
}
export type ElfAttributeCursorAt = (position: number, end: number) => DwarfCursor;
