export interface AlphaPrologState {
  primaryBegins: Set<bigint>;
  secondaryBegins: bigint[];
}

// Digital, Windows NT for Alpha AXP, 15 March 1993, section 9.1 (pp. 69-70):
// an out-of-range PrologEndAddress contains the procedure's beginning address,
// allowing discontiguous segments with their own handlers. Low EM bits are removed
// by the caller. Sets keep resolution linear and independent of directory order.
// https://archive.computerhistory.org/resources/access/text/2024/09/102749943-05-0001-acc.pdf
export const recordAlphaProlog = (state: AlphaPrologState, begin: bigint,
  end: bigint, location: bigint): bigint | null => {
  if (location >= begin && location <= end) {
    state.primaryBegins.add(begin);
    return location;
  }
  state.secondaryBegins.push(location);
  return null;
};

export const finishAlphaPrologs = (state: AlphaPrologState) => {
  let resolvedSecondaryRanges = 0;
  let unresolvedSecondaryRanges = 0;
  for (const begin of state.secondaryBegins) {
    if (state.primaryBegins.has(begin)) resolvedSecondaryRanges++;
    else unresolvedSecondaryRanges++;
  }
  return { resolvedSecondaryRanges, unresolvedSecondaryRanges };
};
