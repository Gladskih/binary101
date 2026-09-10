import type { ElfCfiInstruction, ElfUnwindCie, ElfUnwindFde } from "./unwind-types.js";
import type { ElfCfiRules, ElfCfiRow, ElfCfiEvaluation } from "./cfi-state-types.js";
import { applyElfCfiRule } from "./cfi-rule-updates.js";

const emptyRules = (): ElfCfiRules => ({ cfa: null, registers: {}, returnAddressSigned: false, argumentSize: 0n });
const copyRules = (rules: ElfCfiRules): ElfCfiRules => ({ cfa: rules.cfa,
  registers: { ...rules.registers }, returnAddressSigned: rules.returnAddressSigned,
  argumentSize: rules.argumentSize });
const isLocation = (operation: string): boolean =>
  ["set_loc", "advance_loc", "advance_loc1", "advance_loc2", "advance_loc4"].includes(operation);

const restoreRegister = (rules: ElfCfiRules, defaults: ElfCfiRules, instruction: ElfCfiInstruction): boolean => {
  const register = instruction.operands[0];
  if (typeof register !== "bigint") return false;
  const initial = defaults.registers[String(register)];
  if (initial) rules.registers[String(register)] = initial;
  else delete rules.registers[String(register)];
  return true;
};

const updateState = (rules: ElfCfiRules, defaults: ElfCfiRules, stack: ElfCfiRules[],
  instruction: ElfCfiInstruction, alignment: bigint, issues: string[]): boolean => {
  switch (instruction.operation) {
    case "remember_state":
      if (stack.length >= 4096) { issues.push("CFI state stack limit reached."); return false; }
      stack.push(copyRules(rules));
      return true;
    case "restore_state": {
      const saved = stack.pop();
      if (!saved) { issues.push("CFI state stack underflow."); return false; }
      Object.assign(rules, saved);
      return true;
    }
    case "restore": case "restore_extended": return restoreRegister(rules, defaults, instruction);
    default: return applyElfCfiRule(rules, instruction, alignment);
  }
};

const initialRules = (cie: ElfUnwindCie, issues: string[]): ElfCfiRules | null => {
  const rules = emptyRules();
  const stack: ElfCfiRules[] = [];
  for (const instruction of cie.instructions) {
    if (!updateState(rules, emptyRules(), stack, instruction, cie.dataAlignment, issues)) {
      issues.push(`Unsupported or invalid CIE instruction ${instruction.operation}.`);
      return null;
    }
  }
  return rules;
};

const nextLocation = (row: ElfCfiRow, instruction: ElfCfiInstruction,
  cie: ElfUnwindCie, end: bigint, issues: string[]): bigint | null => {
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
export const evaluateElfCfi = (cie: ElfUnwindCie, fde: ElfUnwindFde): ElfCfiEvaluation => {
  const result: ElfCfiEvaluation = { rows: [], issues: [] };
  if (!fde.start || fde.start.indirect) {
    result.issues.push("CFI rows require a resolved direct FDE start address.");
    return result;
  }
  const defaults = initialRules(cie, result.issues);
  if (!defaults) return result;
  return evaluateFde(cie, fde, fde.start.address, defaults, result);
};

const evaluateFde = (cie: ElfUnwindCie, fde: ElfUnwindFde, start: bigint,
  defaults: ElfCfiRules, result: ElfCfiEvaluation): ElfCfiEvaluation => {
  let row: ElfCfiRow = { ...copyRules(defaults), location: start };
  const stack: ElfCfiRules[] = [];
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
    if (result.rows.length >= 4096) { result.issues.push("CFI row limit reached."); return result; }
  }
  if (row.location < end) result.rows.push(row);
  return result;
};
