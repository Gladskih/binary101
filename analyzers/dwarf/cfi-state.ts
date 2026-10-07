import type { DwarfCfiInstruction, DwarfFrameEncoding } from "./frame-types.js";
import type { DwarfCfiExpression } from "./cfi-state-types.js";
type Cie = Pick<DwarfFrameEncoding, "codeAlignment" | "dataAlignment"> & { instructions: DwarfCfiInstruction<DwarfCfiExpression>[] };
type Fde = { start: bigint | null; range: bigint; instructions: DwarfCfiInstruction<DwarfCfiExpression>[] };
import type { DwarfCfiRules, DwarfCfiRow, DwarfCfiEvaluation } from "./cfi-state-types.js";
import { applyDwarfCfiRule } from "./cfi-rule-updates.js";

const emptyRules = (): DwarfCfiRules => ({ cfa: null, registers: {}, returnAddressSigned: false, argumentSize: 0n });
const copyRules = (rules: DwarfCfiRules): DwarfCfiRules => ({ cfa: rules.cfa,
  registers: { ...rules.registers }, returnAddressSigned: rules.returnAddressSigned,
  argumentSize: rules.argumentSize });
const isLocation = (operation: string): boolean =>
  ["set_loc", "advance_loc", "advance_loc1", "advance_loc2", "advance_loc4", "MIPS_advance_loc8"].includes(operation);

const restoreRegister = (rules: DwarfCfiRules, defaults: DwarfCfiRules,
  instruction: DwarfCfiInstruction<DwarfCfiExpression>): boolean => {
  const register = instruction.operands[0];
  if (typeof register !== "bigint") return false;
  const initial = defaults.registers[String(register)];
  if (initial) rules.registers[String(register)] = initial;
  else delete rules.registers[String(register)];
  return true;
};

const updateState = (rules: DwarfCfiRules, defaults: DwarfCfiRules, stack: DwarfCfiRules[],
  instruction: DwarfCfiInstruction<DwarfCfiExpression>, alignment: bigint, issues: string[]): boolean => {
  switch (instruction.operation) {
    case "remember_state":
      stack.push(copyRules(rules));
      return true;
    case "restore_state": {
      const saved = stack.pop();
      if (!saved) { issues.push("CFI state stack underflow."); return false; }
      Object.assign(rules, saved);
      return true;
    }
    case "restore": case "restore_extended": return restoreRegister(rules, defaults, instruction);
    default: return applyDwarfCfiRule(rules, instruction, alignment);
  }
};

const initialRules = (cie: Cie, issues: string[]): DwarfCfiRules | null => {
  const rules = emptyRules();
  const stack: DwarfCfiRules[] = [];
  for (const instruction of cie.instructions) {
    if (!updateState(rules, emptyRules(), stack, instruction, cie.dataAlignment, issues)) {
      issues.push(`Unsupported or invalid CIE instruction ${instruction.operation}.`);
      return null;
    }
  }
  return rules;
};

const nextLocation = (row: DwarfCfiRow, instruction: DwarfCfiInstruction<DwarfCfiExpression>,
  cie: Cie, end: bigint, issues: string[]): bigint | null => {
  const operand = instruction.operands[0];
  if (typeof operand !== "bigint") { issues.push("Invalid CFI location operand."); return null; }
  const next = instruction.operation === "set_loc" ? operand : row.location + operand * cie.codeAlignment;
  if (next < row.location || (next === row.location && instruction.operation === "set_loc")) {
    issues.push("CFI location does not advance.");
    return null;
  }
  if (next > end) { issues.push("CFI location exceeds the FDE range."); return null; }
  return next;
};

// Evaluate stored instructions into virtual unwind rows, without reading runtime registers.
// DWARF5 6.4.3: https://dwarfstd.org/doc/DWARF5.pdf
export const evaluateDwarfCfi = (cie: Cie, fde: Fde): DwarfCfiEvaluation => {
  const result: DwarfCfiEvaluation = { rows: [], issues: [] };
  if (fde.start == null) {
    result.issues.push("CFI rows require a resolved direct FDE start address.");
    return result;
  }
  const defaults = initialRules(cie, result.issues);
  if (!defaults) return result;
  return evaluateFde(cie, fde, fde.start, defaults, result);
};

const evaluateFde = (cie: Cie, fde: Fde, start: bigint,
  defaults: DwarfCfiRules, result: DwarfCfiEvaluation): DwarfCfiEvaluation => {
  let row: DwarfCfiRow = { ...copyRules(defaults), location: start };
  const stack: DwarfCfiRules[] = [];
  const end = start + fde.range;
  for (const instruction of fde.instructions) {
    if (isLocation(instruction.operation)) {
      const next = nextLocation(row, instruction, cie, end, result.issues);
      if (next == null) return result;
      if (next > row.location) result.rows.push(row);
      row = { ...copyRules(row), location: next };
    } else if (!updateState(row, defaults, stack, instruction, cie.dataAlignment, result.issues)) {
      result.issues.push(`Unsupported or invalid CFI instruction ${instruction.operation}.`);
      return result;
    }
  }
  if (row.location < end) result.rows.push(row);
  return result;
};
