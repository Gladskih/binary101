type Range = { start: bigint; end: bigint };

export const elfRangesCover = (ranges: Range[], start: bigint, end: bigint): boolean => {
  if (start >= end) return start === end;
  const ordered = [...ranges].sort((left, right) =>
    left.start < right.start ? -1 : Number(left.start > right.start));
  let covered = start;
  for (const range of ordered) {
    if (range.start > covered) break;
    if (range.end > covered) covered = range.end;
    if (covered >= end) return true;
  }
  return false;
};
