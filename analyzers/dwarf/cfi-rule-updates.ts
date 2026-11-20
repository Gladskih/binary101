import type { DwarfCfiInstruction } from "./frame-types.js";
import type { DwarfCfiExpression } from "./cfi-state-types.js";
import type { DwarfCfiRules, DwarfCfiRegisterRule } from "./cfi-state-types.js";

type RuleUpdate = (rules: DwarfCfiRules, operands: (bigint | DwarfCfiExpression)[], alignment: bigint) => boolean;
const integer = (value: bigint | DwarfCfiExpression | undefined): bigint | null => typeof value === "bigint" ? value : null;

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
  if (operands[0] == null || typeof operands[0] === "bigint") return false;
  rules.cfa = { expression: operands[0] };
  return true;
};

const setRegister = (rules: DwarfCfiRules, register: bigint | DwarfCfiExpression | undefined,
  rule: DwarfCfiRegisterRule): boolean => {
  if (typeof register !== "bigint" || register < 0n) return false;
  rules.registers[String(register)] = rule;
  return true;
};

const registerOffset = (kind: "offset" | "val_offset"): RuleUpdate => (rules, operands, alignment) => {
  const offset = integer(operands[1]);
  return offset != null && setRegister(rules, operands[0], { kind, offset: offset * alignment });
};
const registerExpression = (kind: "expression" | "val_expression"): RuleUpdate => (rules, operands) =>
  operands[1] != null && typeof operands[1] !== "bigint" && setRegister(rules, operands[0], { kind, expression: operands[1] });

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
  GNU_args_size: (rules, operands) => {
    if (typeof operands[0] !== "bigint") return false;
    rules.argumentSize = operands[0];
    return true;
  }
};

type CfiCodeLocation = { location: bigint; codeAlignment: bigint };

// Arm DWARF ABI: signing with SP+PC carries the signing instruction's address.
// https://github.com/ARM-software/abi-aa/blob/main/aadwarf64/aadwarf64.rst#call-frame-instructions
const setReturnAddressState = (rules: DwarfCfiRules, operands: (bigint | DwarfCfiExpression)[],
  location: CfiCodeLocation | undefined): boolean => {
  const [state, offset] = operands;
  if (typeof state !== "bigint" || typeof offset !== "bigint") return false;
  if (state === 0n) rules.returnAddressState = "unsigned";
  else if (state === 1n) rules.returnAddressState = "signed-sp";
  else if (state === 2n && location) {
    const signingPc = location.location + offset * location.codeAlignment;
    if (signingPc < 0n || signingPc > 0xffff_ffff_ffff_ffffn) return false;
    rules.returnAddressState = { signingPc };
  } else return false;
  return true;
};

export const applyDwarfCfiRule = (rules: DwarfCfiRules, instruction: DwarfCfiInstruction<DwarfCfiExpression>,
  alignment: bigint, location?: CfiCodeLocation): boolean => {
  switch (instruction.operation) {
    case "AARCH64_set_ra_state": return setReturnAddressState(rules, instruction.operands, location);
    case "AARCH64_negate_ra_state":
      if (typeof rules.returnAddressState !== "string") return false;
      rules.returnAddressState = rules.returnAddressState === "unsigned" ? "signed-sp" : "unsigned";
      return true;
    case "AARCH64_negate_ra_state_with_pc":
      if (!location || rules.returnAddressState === "signed-sp") return false;
      return setReturnAddressState(rules,
        [rules.returnAddressState === "unsigned" ? 2n : 0n, 0n], location);
    default: return updates[instruction.operation]?.(rules, instruction.operands, alignment) ?? false;
  }
};
