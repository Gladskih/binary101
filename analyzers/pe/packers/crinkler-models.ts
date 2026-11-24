export interface CrinklerModelPart {
  offset: number;
  unpackedSize: number;
  encodedWeights: number;
  models: { weight: number; contextMask: number }[];
}

// ModelList4k::SetFromModelsAndMask and Crinkler::Recompress.
// https://github.com/runestubbe/Crinkler/blob/f74d964/source/Compressor/ModelList.cpp
// https://github.com/runestubbe/Crinkler/blob/f74d964/source/Crinkler/Crinkler.cpp
const decodeWeights = (encoded: number): { weights: number[]; even: boolean } => {
  const weights: number[] = [];
  let weight = 0;
  for (let bits = encoded; bits !== 0; bits = (bits << 1) >>> 0) {
    if (bits >= 0x80000000) weight += 1;
    else weights.push(weight);
  }
  // The decoder tests x86 parity on AL, so only the low byte is used.
  const parity = (encoded ^ (encoded >>> 4)) & 0xf;
  // 0x6996 encodes odd parity for each possible nibble.
  return { weights, even: ((0x6996 >>> parity) & 1) === 0 };
};

const readPart = (
  view: DataView, offset: number, end: number, sizeWidth: number
) => {
  if (offset + sizeWidth + 4 > end) return null;
  const encodedWeights = view.getUint32(offset + sizeWidth, true);
  const { weights, even } = decodeWeights(encodedWeights);
  const modelsOffset = offset + sizeWidth + 4;
  const next = modelsOffset + weights.length;
  if (next > end) return null;
  return {
    next, even, encodedWeights,
    models: weights.map((weight, index) => ({
      weight, contextMask: view.getUint8(modelsOffset + index)
    }))
  };
};

const readLegacyParts = (
  view: DataView, start: number, end: number, unpackedVa: number
): CrinklerModelPart[] | null => {
  const code = readPart(view, start, end, 4);
  if (!code) return null;
  const data = readPart(view, code.next, end, 4);
  if (!data || data.next !== end) return null;
  // Pre-3.0 records carry negated absolute end addresses for code and data.
  const codeSize = -view.getInt32(start, true) - unpackedVa;
  const dataSize = -view.getInt32(code.next, true) - unpackedVa - codeSize;
  if (codeSize < 0 || dataSize < 0) return null;
  return [
    { offset: start, unpackedSize: codeSize, encodedWeights: code.encodedWeights, models: code.models },
    { offset: code.next, unpackedSize: dataSize,
      encodedWeights: data.encodedWeights, models: data.models }
  ];
};

const readModernParts = (
  view: DataView, start: number, end: number
): CrinklerModelPart[] | null => {
  const parts: CrinklerModelPart[] = [];
  let previous = 0;
  let offset = start;
  while (offset < end) {
    const part = readPart(view, offset, end, 2);
    if (!part) return null;
    // Crinkler 3.0 uses negated cumulative u16 positions and even parity on the last record.
    const position = (-view.getUint16(offset, true)) & 0xffff;
    parts.push({
      offset, unpackedSize: (position - previous) & 0xffff,
      encodedWeights: part.encodedWeights, models: part.models
    });
    if (part.even) return part.next === end ? parts : null;
    offset = part.next;
    previous = position;
  }
  return null;
};

export const readCrinklerModelParts = (
  view: DataView, offset: number, end: number, unpackedVa: number, version: string
): CrinklerModelPart[] | null => {
  if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(end) ||
      offset < 0 || offset >= end || end > view.byteLength) return null;
  return version.startsWith("3.")
    ? readModernParts(view, offset, end)
    : readLegacyParts(view, offset, end, unpackedVa);
};
