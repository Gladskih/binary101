import { readDictionary, unsigned } from "./syntax.js";
import type { PdfDictionary } from "./syntax.js";

export interface XrefPredictor {
  operation: number;
  columns: number;
}

const readColumns = (fields: PdfDictionary["fields"]): number => {
  const columns = unsigned(fields.get("Columns") ?? "1");
  const colors = unsigned(fields.get("Colors") ?? "1");
  const bits = unsigned(fields.get("BitsPerComponent") ?? "8");
  // ISO 32000-2, 7.4.4.4: implement byte-oriented predictors for structural xref data.
  if (!columns || colors !== 1 || bits !== 8) throw new Error("unsupported predictor geometry");
  return columns;
};

const readOperation = (fields: PdfDictionary["fields"]): number => {
  const operation = unsigned(fields.get("Predictor") ?? "1");
  if (operation === 1) return operation;
  if (operation !== 2 && !(operation != null && operation >= 10 && operation <= 15)) {
    throw new Error("unsupported predictor");
  }
  return operation;
};

export const readXrefPredictor = (
  token: string | undefined, rowWidth: number
): XrefPredictor => {
  if (token == null || token === "null") return { operation: 1, columns: rowWidth };
  const dictionary = readDictionary(token);
  if (!dictionary) throw new Error("invalid /DecodeParms");
  const operation = readOperation(dictionary.fields);
  return { operation, columns: operation === 1 ? rowWidth : readColumns(dictionary.fields) };
};

const paeth = (left: number, above: number, diagonal: number): number => {
  // PNG Specification, 9.4: compare distances to the left, above and upper-left bytes.
  const estimate = left + above - diagonal;
  const leftDistance = Math.abs(estimate - left);
  const aboveDistance = Math.abs(estimate - above);
  const diagonalDistance = Math.abs(estimate - diagonal);
  if (leftDistance <= aboveDistance && leftDistance <= diagonalDistance) return left;
  return aboveDistance <= diagonalDistance ? above : diagonal;
};

const contribution = (filter: number, left: number, above: number, diagonal: number): number => {
  switch (filter) {
    case 0: return 0;
    case 1: return left;
    case 2: return above;
    case 3: return (left + above) >>> 1;
    case 4: return paeth(left, above, diagonal);
    default: throw new Error("invalid PNG predictor row filter");
  }
};

const undoPng = (bytes: Uint8Array, columns: number, size: number): Uint8Array => {
  const output = new Uint8Array(size);
  let input = 0;
  for (let row = 0; row < size; row += columns) {
    const filter = bytes[input++]!;
    for (let column = 0; column < columns; column += 1) {
      const index = row + column;
      const left = column > 0 ? output[index - 1]! : 0;
      const above = row > 0 ? output[index - columns]! : 0;
      const diagonal = row > 0 && column > 0 ? output[index - columns - 1]! : 0;
      output[index] = bytes[input++]! + contribution(filter, left, above, diagonal);
    }
  }
  return output;
};

export const undoXrefPredictor = (
  bytes: Uint8Array, predictor: XrefPredictor, size: number
): Uint8Array => {
  const { operation, columns } = predictor;
  const expected = operation >= 10 ? size + size / columns : size;
  if (size % columns || bytes.length !== expected) {
    throw new Error("decoded byte count does not match the declared row layout");
  }
  if (operation >= 10) return undoPng(bytes, columns, size);
  if (operation === 2) {
    for (let i = 0; i < size; i += 1) {
      if (i % columns) bytes[i] = bytes[i]! + bytes[i - 1]!;
    }
  }
  return bytes;
};
