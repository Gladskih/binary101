import type { DwarfExpressionOperation } from "./types.js";
export type DwarfCfiExpression = string | DwarfExpressionOperation[];
export type DwarfCfaRule = { register: bigint; offset: bigint } | { expression: DwarfCfiExpression } | null;
export type DwarfCfiRegisterRule = { kind: "undefined" | "same_value" } |
  { kind: "offset" | "val_offset"; offset: bigint } |
  { kind: "register"; register: bigint } |
  { kind: "expression" | "val_expression"; expression: DwarfCfiExpression };
export interface DwarfCfiRules {
  cfa: DwarfCfaRule;
  registers: Record<string, DwarfCfiRegisterRule>;
  returnAddressSigned: boolean;
  argumentSize: bigint;
}
export interface DwarfCfiRow extends DwarfCfiRules { location: bigint }
export interface DwarfCfiEvaluation { rows: DwarfCfiRow[]; issues: string[] }
