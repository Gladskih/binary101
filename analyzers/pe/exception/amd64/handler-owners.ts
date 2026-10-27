import type { FileRangeReader } from "../../../file-range-reader.js";
import { AMD64_RUNTIME_FUNCTION_ENTRY_SIZE } from "./directory.js";

type FunctionRange = { begin: number; end: number; sourceUnwindInfoRva?: number };

export const readAmd64ChainedFunction = async (
  reader: FileRangeReader, offset: number, issues: string[],
  validateRange: (begin: number, end: number) => boolean
) => {
  // RUNTIME_FUNCTION contains BeginAddress, EndAddress and UnwindData; all 12 bytes matter.
  // https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64#chained-unwind-info-structures
  const tail = await reader.read(offset, AMD64_RUNTIME_FUNCTION_ENTRY_SIZE);
  if (tail.byteLength < AMD64_RUNTIME_FUNCTION_ENTRY_SIZE) {
    issues.push("UNWIND_INFO declares CHAININFO, but the trailing chained RUNTIME_FUNCTION is truncated.");
    return null;
  }
  const validRange = validateRange(tail.getUint32(0, true), tail.getUint32(4, true));
  if (!validRange) issues.push("UNWIND_INFO CHAININFO has an invalid chained function range.");
  return { rva: tail.getUint32(8, true), validRange };
};

const resolveTerminal = (
  origin: number, chains: Map<number, number>, terminals: Map<number, number | null>, issues: string[]
): number | null => {
  const path = new Set<number>();
  let current = origin;
  while (chains.has(current) && !terminals.has(current) && !path.has(current)) {
    path.add(current);
    current = chains.get(current)!;
  }
  const cyclic = path.has(current);
  if (cyclic) issues.push("UNWIND_INFO CHAININFO contains a cycle; handler ownership is unresolved.");
  const terminal = cyclic ? null : terminals.has(current) ? terminals.get(current)! : current;
  for (const address of path) terminals.set(address, terminal);
  return terminal;
};

/** CHAININFO delegates to another RUNTIME_FUNCTION; all child ranges retain that handler.
 * https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64#chained-unwind-info-structures
 * Path compression prevents rescanning shared suffixes; a visited path detects malformed cycles.
 */
export const resolveAmd64HandlerOwners = (
  direct: Map<number, FunctionRange[]>, chains: Map<number, number>, issues: string[]
): Map<number, FunctionRange[]> => {
  const terminals = new Map<number, number | null>();
  const owners = new Map<number, FunctionRange[]>();
  for (const [origin, ranges] of direct) {
    const terminal = resolveTerminal(origin, chains, terminals, issues);
    if (terminal == null) continue;
    const existing = owners.get(terminal) ?? [];
    for (const range of ranges) existing.push(range);
    owners.set(terminal, existing);
  }
  return owners;
};
