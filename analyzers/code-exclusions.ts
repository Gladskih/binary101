/** Validated half-open byte intervals in the decoder's address space. */
export interface CodeExclusion {
  start: bigint;
  end: bigint;
}

export const createCodeExclusionIndex = (ranges: readonly CodeExclusion[] = []) => {
  const merged: CodeExclusion[] = [];
  for (const range of ranges.filter(range => range.start >= 0n && range.end > range.start &&
    range.end <= 0x1_0000_0000_0000_0000n).toSorted((left, right) =>
    left.start < right.start ? -1 : left.start > right.start ? 1 : 0)) {
    const previous = merged.at(-1);
    if (previous && range.start <= previous.end) previous.end =
      range.end > previous.end ? range.end : previous.end;
    else merged.push({ ...range });
  }
  return (address: bigint, length: number): bigint | null => {
    if (!Number.isSafeInteger(length) || length <= 0) return null;
    let lower = 0;
    let upper = merged.length;
    while (lower < upper) {
      const middle = Math.floor((lower + upper) / 2);
      if (merged[middle]!.end <= address) lower = middle + 1;
      else upper = middle;
    }
    const range = merged[lower];
    return range && range.start < address + BigInt(length)
      ? range.start > address ? range.start : address : null;
  };
};
