import { DEFAULT_FILE_READ_WINDOW_BYTES, type FileRangeReader } from "../../file-range-reader.js";

/** Complete rows from a bounded table source, independent of image RVAs. */
export const readRuntimeFunctionChunks = async function* (
  source: FileRangeReader, entryCount: number, entrySize: number,
  truncatedIssue: string, issues: string[]
): AsyncGenerator<DataView> {
  if (!Number.isSafeInteger(entryCount) || entryCount < 0) {
    issues.push("RUNTIME_FUNCTION entry count is invalid.");
    return;
  }
  if (!Number.isSafeInteger(entrySize) || entrySize <= 0) {
    issues.push("RUNTIME_FUNCTION entry size is invalid.");
    return;
  }
  const size = Math.min(entryCount, Math.floor(source.size / entrySize)) * entrySize;
  if (size < entryCount * entrySize) issues.push(truncatedIssue);
  const chunkSize = Math.max(1, Math.floor(DEFAULT_FILE_READ_WINDOW_BYTES / entrySize)) * entrySize;
  for (let offset = 0; offset < size; offset += chunkSize) {
    const requested = Math.min(size - offset, chunkSize);
    const view = await source.read(offset, requested);
    if (view.byteLength < requested) issues.push(truncatedIssue);
    yield new DataView(view.buffer, view.byteOffset,
      Math.floor(Math.min(view.byteLength, requested) / entrySize) * entrySize);
    if (view.byteLength < requested) break;
  }
};
