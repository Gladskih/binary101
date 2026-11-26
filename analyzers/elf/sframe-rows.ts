import type { FileRangeReader } from "../file-range-reader.js";
import type { ElfSFrame, ElfSFrameFunction, ElfSFrameRow } from "./sframe-types.js";

// GNU Binutils SFrame specification §§2.3.2–2.4.1.
// https://sourceware.org/binutils/docs-2.46/sframe-spec.html
const ATTRIBUTE_SIZE = 5;
const FIELD_WIDTHS = [1, 2, 4] as const;
type FieldWidth = (typeof FIELD_WIDTHS)[number];

const signed = (view: DataView, at: number, width: FieldWidth, little: boolean): number => {
  if (width === 1) return view.getInt8(at);
  if (width === 2) return view.getInt16(at, little);
  return view.getInt32(at, little);
};

const pcOffset = (view: DataView, width: FieldWidth, little: boolean): number => {
  if (width === 1) return view.getUint8(0);
  if (width === 2) return view.getUint16(0, little);
  return view.getUint32(0, little);
};

const readAttributes = async (
  reader: FileRangeReader, little: boolean, offset: number, limit: number
): Promise<ElfSFrameFunction["attributes"]> => {
  if (limit - offset < ATTRIBUTE_SIZE) return undefined;
  const view = await reader.read(offset, ATTRIBUTE_SIZE);
  if (view.byteLength !== ATTRIBUTE_SIZE) return undefined;
  return { rowCount: view.getUint16(0, little), info: view.getUint8(2),
    info2: view.getUint8(3), repeatSize: view.getUint8(4) };
};

const decodeRow = (view: DataView, width: FieldWidth, little: boolean,
  functionIndex: number): { row: ElfSFrameRow; size: number } | string => {
  const prefix = width + 1;
  if (view.byteLength < prefix) return "Truncated frame row.";
  const info = view.getUint8(width);
  const wordWidth = FIELD_WIDTHS[(info >> 5) & 3];
  if (!wordWidth) return "Invalid SFrame frame row data width.";
  const wordCount = (info >> 1) & 15;
  const size = prefix + wordCount * wordWidth;
  if (view.byteLength < size) return "Truncated frame row data words.";
  const words = Array.from({ length: wordCount }, (_, index) =>
    signed(view, prefix + index * wordWidth, wordWidth, little));
  return { row: { functionIndex, pcOffset: pcOffset(view, width, little), info, words }, size };
};

const readFunctionRows = async (reader: FileRangeReader, little: boolean, start: number,
  limit: number, entry: ElfSFrameFunction, functionIndex: number, rows: ElfSFrameRow[]
): Promise<void> => {
  let offset = start;
  if (!entry.attributes) {
    const attributes = await readAttributes(reader, little, offset, limit);
    if (!attributes) { entry.issues.push("Truncated SFrame function attributes."); return; }
    entry.attributes = attributes;
    offset += ATTRIBUTE_SIZE;
  }
  const { info, rowCount } = entry.attributes;
  const width = FIELD_WIDTHS[info & 15];
  if (!width) { entry.issues.push("Invalid SFrame frame row PC width."); return; }
  for (let index = 0; index < rowCount; index++) {
    // At most 15 32-bit words follow the PC offset and info byte.
    const view = await reader.read(offset, Math.min(width + 1 + 15 * 4, limit - offset));
    const decoded = decodeRow(view, width, little, functionIndex);
    if (typeof decoded === "string") { entry.issues.push(decoded); return; }
    rows.push(decoded.row);
    offset += decoded.size;
  }
};

export const readSFrameRows = async (reader: FileRangeReader, little: boolean, start: number,
  limit: number, table: ElfSFrame): Promise<void> => {
  // FDE order is unrelated to FRE storage order. Bound each read by the next
  // referenced start so corrupt counts cannot reinterpret another function's bytes.
  const order = table.functions.map((_, index) => index)
    .sort((left, right) => table.functions[left]!.rowOffset - table.functions[right]!.rowOffset);
  for (const [position, index] of order.entries()) {
    const entry = table.functions[index]!;
    const offset = start + entry.rowOffset;
    const nextIndex = order[position + 1];
    const end = nextIndex == null ? limit : Math.min(limit, start + table.functions[nextIndex]!.rowOffset);
    if (offset >= limit) entry.issues.push("SFrame function row offset is outside the FRE area.");
    else if (offset === end) entry.issues.push("Duplicate SFrame function row offset.");
    else await readFunctionRows(reader, little, offset, end, entry, index, table.rows);
  }
};
