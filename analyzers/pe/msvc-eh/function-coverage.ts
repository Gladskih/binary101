import type { PeExceptionDirectory } from "../exception/types.js";
import { isRvaRange } from "../rva-mapping.js";

const completeRuntimeInventory = (exception: PeExceptionDirectory): boolean =>
  exception.issues.length === 0 && exception.invalidEntryCount === 0 &&
  exception.functionCount === exception.beginRvas.length &&
  exception.rangeLengths?.length === exception.beginRvas.length;

/** One merged interval index per parse; no repeated linear searches across .pdata. */
export const createEhFunctionCoverage = (
  exception: PeExceptionDirectory | null
): ((rva: number) => boolean) | null => {
  if (!exception || !completeRuntimeInventory(exception)) return null;
  // Valid .pdata is already ordered. Only malformed/other inventories need an
  // ordering array; avoid a temporary object per runtime function in the common path.
  const order = exception.beginRvas.some((begin, index, begins) => index > 0 && begin < begins[index - 1]!)
    ? Array.from(exception.beginRvas.keys()).sort((left, right) =>
      exception.beginRvas[left]! - exception.beginRvas[right]!) : null;
  const merged: { begin: number; end: number }[] = [];
  for (let index = 0; index < exception.beginRvas.length; index++) {
    const position = order?.[index] ?? index;
    const begin = exception.beginRvas[position]!;
    const length = exception.rangeLengths![position]!;
    if (!isRvaRange(begin, length)) return null;
    const previous = merged[merged.length - 1];
    const end = begin + length;
    if (previous && begin <= previous.end) previous.end = Math.max(previous.end, end);
    else merged.push({ begin, end });
  }
  return rva => {
    let low = 0, high = merged.length;
    while (low < high) {
      const middle = Math.floor((low + high) / 2);
      const range = merged[middle]!;
      if (rva < range.begin) high = middle;
      // End labels may appear in IP maps. Presence of the exact owner start is not required:
      // LLVM WinException::computeIP2StateTable deliberately omits cleanup-funclet maps.
      // https://github.com/llvm/llvm-project/blob/main/llvm/lib/CodeGen/AsmPrinter/WinException.cpp
      else if (rva <= range.end) return true;
      else low = middle + 1;
    }
    return false;
  };
};
