import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";

export interface LegacyCodeViewIndex { algorithm: number; counts?: number[]; }

// TIS 7.5 defines name hash 10 and address sort 12. Older 32-bit layouts
// are decoded by Microsoft's unchanged SymHash32 / AddrHash32 / AddrHash32NB09.
// https://openwatcom.org/ftp/devel/docs/CodeView.pdf
// https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/cvdump/dumpsym7.cpp#L6653
interface CodeViewIndexLayout { countBytes: 2 | 4; itemBytes: 4 | 8; alignment: 2 | 4; }
const NAME_LAYOUTS = new Map<number, CodeViewIndexLayout>([
  [2, { countBytes: 2, itemBytes: 4, alignment: 2 }],
  [6, { countBytes: 2, itemBytes: 4, alignment: 2 }],
  [10, { countBytes: 4, itemBytes: 8, alignment: 4 }]
]);
const ADDRESS_LAYOUTS = new Map<number, CodeViewIndexLayout>([
  [4, { countBytes: 2, itemBytes: 4, alignment: 2 }],
  [5, { countBytes: 2, itemBytes: 4, alignment: 4 }],
  [8, { countBytes: 2, itemBytes: 8, alignment: 2 }],
  [12, { countBytes: 4, itemBytes: 8, alignment: 4 }]
]);

const readCounts = async (reader: LegacyCodeViewReader, layout: CodeViewIndexLayout): Promise<number[]> => {
  const count = (await reader.view(0, 4)).getUint16(0, true);
  // TIS calls the second WORD alignment filler and does not prescribe its bytes.
  const base = Math.ceil((4 + count * (4 + layout.countBytes)) / layout.alignment) * layout.alignment;
  const table = await reader.view(4, base - 4);
  const counts: number[] = [];
  let sequentialOffset = 0;
  for (let index = 0; index < count; index++) {
    // Only TIS's DWORD-count layouts specify a chain-relative offset origin.
    // For the older WORD-count layouts, validate the sequential chains exactly
    // as cvdump reads them, without guessing what their stored offsets denote.
    const offset = layout.countBytes === 4 ? table.getUint32(index * 4, true) : sequentialOffset;
    const cursor = count * 4 + index * layout.countBytes;
    const entries = layout.countBytes === 4 ? table.getUint32(cursor, true) : table.getUint16(cursor, true);
    counts.push(entries);
    sequentialOffset = offset + entries * layout.itemBytes;
    if (offset % layout.itemBytes !== 0 || entries * layout.itemBytes > reader.size - base - offset) {
      reader.warn(`CodeView index group ${index + 1} has a misaligned or truncated chain.`);
    }
  }
  return counts;
};

const readIndex = async (reader: LegacyCodeViewReader, algorithm: number,
  layouts: ReadonlyMap<number, CodeViewIndexLayout>): Promise<LegacyCodeViewIndex | undefined> => {
  if (algorithm === 0 && reader.size === 0) return undefined;
  if (algorithm === 0) {
    reader.warn("CodeView index has bytes although its algorithm is 0 (no index).");
    return { algorithm };
  }
  const layout = layouts.get(algorithm);
  if (!layout) {
    reader.warn(`CodeView index algorithm ${algorithm} is not decoded.`);
    return { algorithm };
  }
  try { return { algorithm, counts: await readCounts(reader, layout) }; }
  catch (error) { reader.warn(`CodeView index counts: ${String(error)}`); return { algorithm }; }
};

export const readLegacyCodeViewNameIndex = (reader: LegacyCodeViewReader, algorithm: number) =>
  readIndex(reader, algorithm, NAME_LAYOUTS);

export const readLegacyCodeViewAddressIndex = (reader: LegacyCodeViewReader, algorithm: number) =>
  readIndex(reader, algorithm, ADDRESS_LAYOUTS);
