import type { LegacyCodeViewData } from "../../analyzers/pe/debug/legacy-codeview.js";
import type { LegacyCodeViewSymbol } from "../../analyzers/pe/debug/legacy-codeview-symbol-records.js";
import { legacyCodeViewSymbolName, legacyCodeViewTypeName } from "./legacy-codeview-kinds.js";

interface LegacyCodeViewSymbolNode { record: LegacyCodeViewSymbol; container?: string; }

function* symbolRoots(data: LegacyCodeViewData): Generator<LegacyCodeViewSymbolNode> {
  if (data.kind === "symbols") for (const record of data.records) yield { record };
  if (data.kind === "types") for (const type of data.records) for (const record of type.symbols ?? []) {
    yield { record, container: legacyCodeViewTypeName(type.type) };
  }
}

/** Nearest-container labels avoid constructing quadratic ancestry strings for deep input. */
export function* iterateLegacyCodeViewSymbols(data: LegacyCodeViewData): Generator<LegacyCodeViewSymbolNode> {
  const pending = [...symbolRoots(data)].reverse();
  while (pending.length) {
    const node = pending.pop()!;
    yield node;
    const children = node.record.children ?? [];
    for (let index = children.length - 1; index >= 0; index--) {
      pending.push({ record: children[index]!, container: legacyCodeViewSymbolName(node.record.type) });
    }
  }
}
