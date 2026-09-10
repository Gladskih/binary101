import type { ElfCfiInstruction } from "./unwind-types.js";
import type { ElfCfiRules, ElfCfiRegisterRule } from "./cfi-state-types.js";

type RuleUpdate = (rules: ElfCfiRules, operands: (bigint | string)[], alignment: bigint) => boolean;
const integer = (value: bigint | string | undefined): bigint | null => typeof value === "bigint" ? value : null;

const defineCfa: RuleUpdate = (rules, operands) => {
  const register = integer(operands[0]);
  const offset = integer(operands[1]);
  if (register == null || offset == null) return false;
  rules.cfa = { register, offset };
  return true;
};
const cfaRegister: RuleUpdate = (rules, operands) => {
  const register = integer(operands[0]);
  if (register == null || !rules.cfa || !("register" in rules.cfa)) return false;
  rules.cfa = { ...rules.cfa, register };
  return true;
};
const cfaOffset: RuleUpdate = (rules, operands) => {
  const offset = integer(operands[0]);
  if (offset == null || !rules.cfa || !("register" in rules.cfa)) return false;
  rules.cfa = { ...rules.cfa, offset };
  return true;
};
const cfaExpression: RuleUpdate = (rules, operands) => {
  if (typeof operands[0] !== "string") return false;
  rules.cfa = { expression: operands[0] };
  return true;
};

const setRegister = (rules: ElfCfiRules, register: bigint | string | undefined,
  rule: ElfCfiRegisterRule): boolean => {
  if (typeof register !== "bigint" || register < 0n) return false;
  rules.registers[String(register)] = rule;
  return true;
};

const registerOffset = (kind: "offset" | "val_offset"): RuleUpdate => (rules, operands, alignment) => {
  const offset = integer(operands[1]);
  return offset != null && setRegister(rules, operands[0], { kind, offset: offset * alignment });
};
const registerExpression = (kind: "expression" | "val_expression"): RuleUpdate => (rules, operands) =>
  typeof operands[1] === "string" && setRegister(rules, operands[0], { kind, expression: operands[1] });

// DWARF5 6.4.2.2-3: unscaled CFA offsets versus signed factored forms.
// https://dwarfstd.org/doc/DWARF5.pdf
const updates: Readonly<Record<string, RuleUpdate>> = {
  def_cfa: defineCfa,
  def_cfa_sf: (rules, operands, alignment) => typeof operands[1] === "bigint" &&
    defineCfa(rules, [operands[0]!, operands[1] * alignment], alignment),
  def_cfa_register: cfaRegister,
  def_cfa_offset: cfaOffset,
  def_cfa_offset_sf: (rules, operands, alignment) => typeof operands[0] === "bigint" &&
    cfaOffset(rules, [operands[0] * alignment], alignment),
  def_cfa_expression: cfaExpression,
  offset: registerOffset("offset"), offset_extended: registerOffset("offset"),
  offset_extended_sf: registerOffset("offset"), val_offset: registerOffset("val_offset"),
  val_offset_sf: registerOffset("val_offset"),
  GNU_negative_offset_extended: (rules, operands, alignment) => registerOffset("offset")(rules, operands, -alignment),
  undefined: (rules, operands) => setRegister(rules, operands[0], { kind: "undefined" }),
  same_value: (rules, operands) => setRegister(rules, operands[0], { kind: "same_value" }),
  register: (rules, operands) => typeof operands[1] === "bigint" &&
    setRegister(rules, operands[0], { kind: "register", register: operands[1] }),
  expression: registerExpression("expression"), val_expression: registerExpression("val_expression"),
  nop: () => true,
  AARCH64_negate_ra_state: rules => { rules.returnAddressSigned = !rules.returnAddressSigned; return true; },
  GNU_args_size: (rules, operands) => {
    if (typeof operands[0] !== "bigint") return false;
    rules.argumentSize = operands[0];
    return true;
  }
};

export const applyElfCfiRule = (rules: ElfCfiRules, instruction: ElfCfiInstruction,
  alignment: bigint): boolean => updates[instruction.operation]?.(rules, instruction.operands, alignment) ?? false;
