import { dwarfAttributeValue, dwarfNumericValue } from "./attribute-values.js";
import type { DwarfMacroUnit } from "./macro-types.js";
import type { DwarfStringReader } from "./strings.js";
import type { DwarfUnit } from "./types.js";

const imports = (unit: DwarfMacroUnit): bigint[] => unit.entries.flatMap(entry => {
  const offset = entry.opcode === 7 ? dwarfNumericValue(entry.operands[0]) : null;
  return offset == null ? [] : [offset];
});

const validateImports = (units: DwarfMacroUnit[], issues: string[]): void => {
  const byOffset = new Map(units.filter(unit => unit.version != null).map(unit => [BigInt(unit.offset), unit]));
  const complete = new Set<DwarfMacroUnit>();
  const active = new Set<DwarfMacroUnit>();
  for (const unit of byOffset.values()) {
    if (complete.has(unit)) continue;
    const pending = [{ unit, imports: imports(unit) }];
    active.add(unit);
    while (pending.length) {
      const frame = pending.at(-1)!;
      const offset = frame.imports.pop();
      if (offset == null) {
        active.delete(frame.unit); complete.add(frame.unit); pending.pop(); continue;
      }
      const target = byOffset.get(offset);
      if (!target) issues.push(`.debug_macro: import ${offset} does not identify a macro unit.`);
      else if (active.has(target)) issues.push(".debug_macro: cyclic macro imports.");
      else if (!complete.has(target)) {
        active.add(target); pending.push({ unit: target, imports: imports(target) });
      }
    }
  }
};

const macroOwner = (units: DwarfUnit[], macro: DwarfMacroUnit): DwarfUnit[] => units.filter(unit => {
  const root = unit.dies[0];
  const offset = macro.version == null ? dwarfNumericValue(dwarfAttributeValue(root, 0x43))
    : dwarfNumericValue(dwarfAttributeValue(root, 0x79) ?? dwarfAttributeValue(root, 0x2119));
  return offset === BigInt(macro.offset);
}); // DW_AT_macro_info / macros / GNU_macros: DWARF 5 3.1.1; LLVM Dwarf.def.

const linkOwners = (macros: DwarfMacroUnit[], units: DwarfUnit[]): Map<DwarfMacroUnit, Set<DwarfUnit>> => {
  const owners = new Map<DwarfMacroUnit, Set<DwarfUnit>>();
  const byOffset = new Map(macros.filter(macro => macro.version != null).map(macro => [BigInt(macro.offset), macro]));
  for (const macro of macros) {
    for (const owner of macroOwner(units, macro)) {
      const pending = [macro];
      const visited = new Set<DwarfMacroUnit>();
      while (pending.length) {
        const current = pending.pop()!;
        if (visited.has(current)) continue;
        visited.add(current);
        if (!owners.has(current)) owners.set(current, new Set());
        owners.get(current)!.add(owner);
        for (const offset of imports(current)) {
          const imported = byOffset.get(offset);
          if (imported) pending.push(imported);
        }
      }
    }
  }
  return owners;
};

const resolveIndexedStrings = async (macro: DwarfMacroUnit, owners: Set<DwarfUnit> | undefined,
  strings: DwarfStringReader, issues: string[]): Promise<void> => {
  if (!macro.entries.some(entry => entry.operands.some(operand => operand.kind === "string-index"))) return;
  const contexts = new Map([...owners ?? []].map(owner => {
    const base = dwarfNumericValue(dwarfAttributeValue(owner.dies[0], 0x72));
    return [`${owner.version}:${owner.format}:${base}`, { version: owner.version,
      format: owner.format, addressSize: owner.addressSize, stringOffsetsBase: base }];
  }));
  if (contexts.size !== 1) {
    issues.push(`${macro.sectionName}: indexed macro strings have no unique importing unit context.`);
    return;
  }
  for (const entry of macro.entries) {
    for (const [index, value] of entry.operands.entries()) {
      if (value.kind !== "string-index") continue;
      const text = await strings.resolve(value, contexts.values().next().value!);
      if (text != null) entry.operands[index] = { kind: "string", value: text };
    }
  }
};

export const linkDwarfMacros = async (macros: DwarfMacroUnit[], units: DwarfUnit[],
  strings: DwarfStringReader, issues: string[]): Promise<void> => {
  validateImports(macros, issues);
  const owners = linkOwners(macros, units);
  for (const macro of macros) await resolveIndexedStrings(macro, owners.get(macro), strings, issues);
};
