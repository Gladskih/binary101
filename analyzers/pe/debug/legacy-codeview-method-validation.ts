import type { LegacyCodeViewTypeRecord } from "./legacy-codeview-type-records.js";
import type { LegacyCodeViewField } from "./legacy-codeview-fields.js";

// TIS 3.4 LF_METHOD: the field's count determines repetitions in LF_METHODLIST.
// https://openwatcom.org/ftp/devel/docs/CodeView.pdf
const OVERLOADED_METHODS = new Set([0x408, 0x1407, 0x150f]);

const methodCounts = (records: readonly LegacyCodeViewTypeRecord[]): ReadonlyMap<number, number | undefined> => {
  const counts = new Map<number, number | undefined>();
  for (const record of records) {
    if (record.index === undefined) continue;
    counts.set(record.index, !counts.has(record.index) && record.shape?.kind === "methods"
      ? record.shape.methods.length : undefined);
  }
  return counts;
};

const checkMethodCount = (member: LegacyCodeViewField, counts: ReadonlyMap<number, number | undefined>,
  warn: (message: string) => void): void => {
  if (!OVERLOADED_METHODS.has(member.type) || member.typeIndex === undefined
    || member.methodCount === undefined) return;
  const available = counts.get(member.typeIndex);
  if (available === undefined || available >= member.methodCount) return;
  warn(`CodeView overloaded method ${member.name || "(unnamed)"}: declared variants ${member.methodCount}; ` +
    `recovered variants ${available}. Some method declarations are unavailable.`);
};

/** Check only resolved local lists; external and ambiguous identities remain unresolved. */
export const validateCodeViewMethodLists = (records: readonly LegacyCodeViewTypeRecord[],
  warn: (message: string) => void): void => {
  const counts = methodCounts(records);
  for (const record of records) {
    if (record.index === undefined) continue;
    for (const member of record.members ?? []) checkMethodCount(member, counts, warn);
  }
};
