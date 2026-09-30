/** Addresses belong to the adapter's image coordinate system (RVAs for PE).
 * Only unambiguous, relocated, file-backed pointer sites may enter pointers. */
export interface ItaniumRttiImage {
  pointerSize: 4 | 8;
  pointers: Map<number, number>;
  relocations: Set<number>;
  /** Physical ordering key for sparse reads. */
  readOrder: (address: number) => number;
  read: (address: number, size: number) => Promise<DataView>;
  isExecutable: (address: number) => boolean;
}

export type ItaniumClassKind = "class" | "si" | "vmi";
export interface ItaniumBase {
  typeAddress: number;
  /** For virtual bases this is a vtable slot displacement, not an object offset. */
  offset: number;
  isVirtual: boolean;
  isPublic: boolean;
}
export interface ItaniumType {
  address: number;
  name: string;
  kind: ItaniumClassKind;
  bases: ItaniumBase[];
  flags?: number;
}
export interface ItaniumRttiAnalysis {
  types: ItaniumType[];
  warnings: string[];
}
