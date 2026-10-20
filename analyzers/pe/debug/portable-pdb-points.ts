import { readCompressedUInt } from "../clr/metadata-heaps.js";

// Sequence Points Blob and ECMA-335 II.23.2 compressed signed integers:
// https://github.com/dotnet/runtime/blob/main/docs/design/specs/PortablePdb-Metadata.md
class PointCursor {
  offset = 0;
  constructor(readonly bytes: Uint8Array) {}
  unsigned(): number {
    const result = readCompressedUInt(this.bytes, this.offset);
    if (!result) throw new Error("compressed integer is malformed or truncated");
    this.offset += result.size;
    return result.value;
  }
  signed(): number {
    const start = this.offset;
    const value = this.unsigned();
    const bits = ({ 1: 6, 2: 13, 4: 28 } as Record<number, number>)[this.offset - start]!;
    return (value >>> 1) - ((value & 1) ? 2 ** bits : 0);
  }
}

const readPosition = (
  cursor: PointCursor, previous: [number, number] | null
): [number, number] => previous
  ? [previous[0] + cursor.signed(), previous[1] + cursor.signed()]
  : [cursor.unsigned(), cursor.unsigned()];

const validateDocument = (document: number, count: number): void => {
  if (document === 0 || document > count) throw new Error("document index is outside Document table");
};

const validSourceLine = (value: number): boolean =>
  value >= 0 && value < 0x20000000 && value !== 0xfeefee;

const validSourceColumn = (value: number): boolean => value >= 0 && value < 0x10000;

const validatePosition = (position: [number, number], lines: number, columns: number): void => {
  const [line, column] = position;
  if (!validSourceLine(line) || !validSourceLine(line + lines) ||
      !validSourceColumn(column) || !validSourceColumn(column + columns)) {
    throw new Error("sequence point has an invalid source position");
  }
};

interface SequencePointState {
  position: [number, number] | null;
  ilOffset: number;
  first: boolean;
  counts: { visible: number; hidden: number };
}

const readSequencePoint = (cursor: PointCursor, state: SequencePointState, documentCount: number): void => {
  const delta = cursor.unsigned();
  if (!state.first && delta === 0) {
    validateDocument(cursor.unsigned(), documentCount);
    return;
  }
  state.ilOffset += delta;
  if (state.ilOffset >= 0x20000000) throw new Error("sequence point IL offset is out of range");
  const lines = cursor.unsigned();
  const columns = lines === 0 ? cursor.unsigned() : cursor.signed();
  if (lines === 0 && columns === 0) state.counts.hidden++;
  else {
    state.position = readPosition(cursor, state.position);
    validatePosition(state.position, lines, columns);
    state.counts.visible++;
  }
  state.first = false;
};

export const summarizeSequencePoints = (
  bytes: Uint8Array, initialDocument: number, documentCount: number, issues: string[]
): { visible: number; hidden: number } => {
  const result = { visible: 0, hidden: 0 };
  if (!bytes.length) return result;
  const cursor = new PointCursor(bytes);
  const state: SequencePointState = { position: null, ilOffset: 0, first: true, counts: result };
  try {
    cursor.unsigned(); // LocalSignature, followed by InitialDocument only for multi-document methods.
    validateDocument(initialDocument || cursor.unsigned(), documentCount);
    while (cursor.offset < bytes.length) {
      readSequencePoint(cursor, state, documentCount);
    }
    if (state.first) throw new Error("sequence point blob has no sequence points");
  } catch (error) {
    issues.push(`Portable PDB sequence points: ${(error as Error).message}.`);
  }
  return result;
};
