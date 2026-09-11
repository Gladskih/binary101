import type { DwarfCursor } from "../dwarf/cursor.js";
import type { ElfUnwindPointer } from "./unwind-types.js";

export interface ElfLsdaCallSite { start: bigint; length: bigint; landingPad: bigint; action: bigint }
export interface ElfLsdaAction { offset: number; typeFilter: bigint; nextOffset: bigint }
export interface ElfLsda {
  address: bigint;
  landingPadBase: ElfUnwindPointer | null;
  typeEncoding: number;
  callSiteEncoding: number;
  callSites: ElfLsdaCallSite[];
  actions: ElfLsdaAction[];
  types: { index: bigint; pointer: ElfUnwindPointer | null }[];
  specifications: { filter: bigint; typeIndices: bigint[] }[];
  issues: string[];
}
export type ElfLsdaCursorAt = (position: number, end?: number) => DwarfCursor;
