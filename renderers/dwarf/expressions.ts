import type { DwarfExpressionOperation } from "../../analyzers/dwarf/types.js";
import { dwarfOperationName } from "../../analyzers/dwarf/operation-names.js";

const signedOffset = (value: bigint | Uint8Array | DwarfExpressionOperation[] | undefined): string =>
  typeof value === "bigint" ? `${value < 0n ? "−" : "+"}${value < 0n ? -value : value} bytes` : "?";

const simpleOperation = (operation: DwarfExpressionOperation): string | null => {
  if (operation.incomplete) return `incomplete ${dwarfOperationName(operation.opcode)}`;
  // Register ranges and frame-base operations: DWARF 5 2.5.1/7.7.1.
  if (operation.opcode >= 0x50 && operation.opcode <= 0x6f) {
    return `DWARF register ${operation.opcode - 0x50}`;
  }
  if (operation.opcode >= 0x70 && operation.opcode <= 0x8f) {
    return `register ${operation.opcode - 0x70} ${signedOffset(operation.operands[0])}`;
  }
  return namedOperation(operation);
};

const namedOperation = (operation: DwarfExpressionOperation): string | null => {
  if (operation.opcode === 0x91) return `frame base ${signedOffset(operation.operands[0])}`;
  if (operation.opcode === 0x9c) return "canonical frame address";
  if (operation.opcode === 0x9f) return "value rather than an address";
  if (operation.opcode === 0x03) return "static storage address";
  if (operation.opcode === 0x93) return `${String(operation.operands[0] ?? "?")}-byte piece`;
  if (operation.opcode >= 0x30 && operation.opcode <= 0x4f) {
    return `literal ${operation.opcode - 0x30}`;
  }
  return null;
};

// Iterative formatting also handles deeply nested DW_OP_entry_value expressions.
export const dwarfExpressionText = (operations: DwarfExpressionOperation[]): string => {
  const pieces: string[] = [];
  const pending: Array<string | DwarfExpressionOperation> = [...operations].reverse();
  while (pending.length) {
    const item = pending.pop()!;
    if (typeof item === "string") { pieces.push(item); continue; }
    const simple = simpleOperation(item);
    if (simple) { pieces.push(simple); continue; }
    const nested = item.operands.find(operand => Array.isArray(operand));
    if (Array.isArray(nested)) {
      pieces.push(`${dwarfOperationName(item.opcode)} (`);
      pending.push(")", ...[...nested].reverse());
    } else {
      pieces.push(dwarfOperationName(item.opcode).replaceAll("_", " ") +
        (item.operands.length ? ` ${item.operands.map(operand => typeof operand === "bigint"
          ? operand.toString() : `${operand.length}-byte value`).join(", ")}` : ""));
    }
  }
  return pieces.join("; ").replaceAll("(; ", "(").replaceAll("; )", ")");
};
