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
  const ranges = exception.beginRvas.map((begin, index) => ({ begin, length: exception.rangeLengths![index]! }));
  if (ranges.some(range => !isRvaRange(range.begin, range.length))) return null;
  const merged: { begin: number; end: number }[] = [];
  for (const range of ranges.sort((left, right) => left.begin - right.begin)) {
    const previous = merged[merged.length - 1];
    const end = range.begin + range.length;
    if (previous && range.begin <= previous.end) previous.end = Math.max(previous.end, end);
    else merged.push({ begin: range.begin, end });
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
