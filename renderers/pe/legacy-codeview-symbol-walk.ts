import type { LegacyCodeViewData } from "../../analyzers/pe/debug/legacy-codeview.js";
import type { LegacyCodeViewSymbol } from "../../analyzers/pe/debug/legacy-codeview-symbol-records.js";
import { legacyCodeViewSymbolName, legacyCodeViewTypeName } from "./legacy-codeview-kinds.js";

export interface LegacyCodeViewSymbolNode {
  record: LegacyCodeViewSymbol;
  container?: string;
  addressContext?: "type" | "discarded";
}

function* symbolRoots(data: LegacyCodeViewData): Generator<LegacyCodeViewSymbolNode> {
  if (data.kind === "symbols") for (const record of data.records) yield { record };
  if (data.kind === "types") for (const type of data.records) for (const record of type.symbols ?? []) {
    yield { record, container: legacyCodeViewTypeName(type.type), addressContext: "type" };
  }
}

/** Nearest-container labels avoid constructing quadratic ancestry strings for deep input. */
export function* iterateLegacyCodeViewSymbols(data: LegacyCodeViewData): Generator<LegacyCodeViewSymbolNode> {
  const pending = [...symbolRoots(data)].reverse();
  while (pending.length) {
    const node = pending.pop()!;
    yield node;
    const children = node.record.children ?? [];
    // DISCARDEDSYM retains original symbols, whose former addresses may have been
    // reused by unrelated image code. Preserve this context through nested containers.
    // https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h#L4538
    const addressContext = node.record.type === 0x113b ? "discarded" : node.addressContext;
    for (let index = children.length - 1; index >= 0; index--) {
      pending.push({ record: children[index]!, container: legacyCodeViewSymbolName(node.record.type),
        ...(addressContext ? { addressContext } : {}) });
    }
  }
}
