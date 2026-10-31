import type { FileRangeReader } from "../file-range-reader.js";
import type { ResourceDecodeResult, ResourceRange } from "./types.js";

export const requireResource = (condition: unknown, message: string): void => {
  if (!condition) throw new Error(message);
};

export const validResourceRange = (offset: number, size: number, limit: number): boolean =>
  Number.isSafeInteger(offset) && Number.isSafeInteger(size) &&
  offset >= 0 && size >= 0 && offset <= limit - size;

export const readResource = async (
  reader: FileRangeReader, range: ResourceRange, offset: number, size: number
): Promise<DataView> => {
  requireResource(validResourceRange(range.offset, range.size, reader.size), "Resource range is outside the file");
  requireResource(validResourceRange(offset, size, range.size), "Resource structure is truncated or out of bounds");
  const view = await reader.read(range.offset + offset, size);
  requireResource(view.byteLength === size, "Resource read is truncated");
  return view;
};

export const resourceBytes = (view: DataView): Uint8Array =>
  new Uint8Array(view.buffer, view.byteOffset, view.byteLength);

export const inspectResource = async <Type>(
  parse: () => Promise<Type>
): Promise<ResourceDecodeResult<Type>> => {
  try {
    return { value: await parse(), issues: [] };
  } catch (error) {
    return { value: null, issues: [error instanceof Error ? error.message : String(error)] };
  }
};
