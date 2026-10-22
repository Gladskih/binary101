import { legacyU16, legacyU32 } from "./pe-legacy-codeview.js";

// TIS 7.5: DWORD counts, chain-relative offsets and two-DWORD chain items.
export const codeViewHashIndex = (counts: readonly number[], countWidth = 4, entryWidth = 8): number[] => {
  let offset = 0;
  const offsets = counts.flatMap(count => {
    const bytes = legacyU32(offset);
    offset += count * entryWidth;
    return bytes;
  });
  return [...legacyU16(counts.length), 0, 0, ...offsets,
    ...counts.flatMap(count => countWidth === 4 ? legacyU32(count) : legacyU16(count)),
    ...new Array<number>(offset).fill(0)];
};

export const codeViewGlobalSymbols = (records: readonly number[], names: readonly number[],
  addresses: readonly number[], nameAlgorithm = 10, addressAlgorithm = 12): number[] => [
  ...legacyU16(nameAlgorithm), ...legacyU16(addressAlgorithm), ...legacyU32(records.length),
  ...legacyU32(names.length), ...legacyU32(addresses.length), ...records, ...names, ...addresses
];

export const codeViewAddressIndex = (counts: readonly number[], algorithm: number): number[] => {
  const bytes = codeViewHashIndex(counts, algorithm === 12 ? 4 : 2, [8, 12].includes(algorithm) ? 8 : 4);
  if (algorithm === 5 && counts.length % 2 !== 0) bytes.splice(4 + counts.length * 6, 0, 0, 0);
  return bytes;
};
