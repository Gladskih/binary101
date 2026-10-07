export type ElfDwarfRelocationKind = {
  width: number;
  operation: "absolute" | "relative" | "add" | "subtract";
  overflow: "unsigned" | "signed" | "mixed" | "truncate";
};
export type ElfDwarfPatch = { offset: number; bytes: Uint8Array };
