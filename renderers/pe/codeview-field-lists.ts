import type { LegacyCodeViewTypeRecord } from "../../analyzers/pe/debug/legacy-codeview-type-records.js";

export interface CodeViewFieldListResolution {
  lists: LegacyCodeViewTypeRecord[];
  issues: string[];
}
type TraversalStep = { kind: "enter" | "leave"; index: number };

const fieldListIssue = (index: number, record: LegacyCodeViewTypeRecord | null | undefined): string | undefined => {
  if (record === null) return `ambiguous field list #${index}`;
  if (!record) return `missing field list #${index}`;
  if (record.type !== 0x204 && record.type !== 0x1203) return `type #${index} is not a field list`;
  return undefined;
};

const resolveLists = (initial: number,
  indexed: ReadonlyMap<number, LegacyCodeViewTypeRecord | null>): CodeViewFieldListResolution => {
  const result: CodeViewFieldListResolution = { lists: [], issues: [] };
  const states = new Map<number, TraversalStep["kind"]>();
  const pending: TraversalStep[] = [{ kind: "enter", index: initial }];
  while (pending.length) {
    const step = pending.pop()!;
    if (step.kind === "leave") { states.set(step.index, "leave"); continue; }
    if (states.get(step.index) === "enter") result.issues.push(`cyclic field-list continuation #${step.index}`);
    if (states.has(step.index)) continue;
    states.set(step.index, "enter");
    const record = indexed.get(step.index);
    const issue = fieldListIssue(step.index, record);
    if (issue) { result.issues.push(issue); states.set(step.index, "leave"); continue; }
    result.lists.push(record!);
    pending.push({ kind: "leave", index: step.index });
    // Reverse the stack insertion, preserving the stored continuation order.
    const members = record!.members ?? [];
    for (let index = members.length - 1; index >= 0; index--) {
      const continuation = members[index]!.continuation;
      if (continuation !== undefined) pending.push({ kind: "enter", index: continuation });
    }
  }
  return result;
};

/** Resolve a subsection's local namespace iteratively; shared list heads are cached. */
export const createCodeViewFieldListResolver = (indexed: ReadonlyMap<number, LegacyCodeViewTypeRecord | null>) => {
  const completed = new Map<number, CodeViewFieldListResolution>();
  return (index: number): CodeViewFieldListResolution => {
    if (!completed.has(index)) completed.set(index, resolveLists(index, indexed));
    return completed.get(index)!;
  };
};
