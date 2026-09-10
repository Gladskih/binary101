export type ElfCfaRule = { register: bigint; offset: bigint } | { expression: string } | null;
export type ElfCfiRegisterRule = { kind: "undefined" | "same_value" } |
  { kind: "offset" | "val_offset"; offset: bigint } |
  { kind: "register"; register: bigint } |
  { kind: "expression" | "val_expression"; expression: string };
export interface ElfCfiRules {
  cfa: ElfCfaRule;
  registers: Record<string, ElfCfiRegisterRule>;
  returnAddressSigned: boolean;
  argumentSize: bigint;
}
export interface ElfCfiRow extends ElfCfiRules { location: bigint }
export interface ElfCfiEvaluation { rows: ElfCfiRow[]; issues: string[] }
