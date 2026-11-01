import { DEFAULT_FILE_READ_WINDOW_BYTES, type FileRangeReader } from "../../../file-range-reader.js";
import { mappedRvaSpan } from "../../rva-mapping.js";
import { readMappedRvaPrefix } from "../../rva-byte-reader.js";
import type { RvaToOffset } from "../../types.js";

// CountOfCodes/PayloadWords is a byte: header + 510 payload bytes + alignment
// + a 12-byte chained RUNTIME_FUNCTION fit in 528 bytes.
// https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64#struct-unwind_info
const MAX_UNWIND_BLOCK_BYTES = 528;

/** Keep one local source window: the sorted scan should not consult the shared
 * LRU or remap each field of every unwind record (profiled 2.22 s scan).
 */
export const createAmd64UnwindBlockReader = (reader: FileRangeReader, rvaToOff: RvaToOffset) => {
  let offset = 0;
  let window: DataView = new DataView(new ArrayBuffer(0));
  const blockAt = (start: number): DataView => new DataView(window.buffer,
    window.byteOffset + start - offset, Math.min(MAX_UNWIND_BLOCK_BYTES, window.byteLength - (start - offset)));
  return (rva: number): DataView | Promise<DataView> => {
    // Only an authoritative span mapper proves the entire window's continuity.
    // Fragmented mappings retain the existing readable-prefix assembly.
    const span = rvaToOff.span
      ? mappedRvaSpan(rvaToOff, rva, DEFAULT_FILE_READ_WINDOW_BYTES, reader.size) : null;
    if (!span || span.size < MAX_UNWIND_BLOCK_BYTES) {
      return readMappedRvaPrefix(reader, rva, MAX_UNWIND_BLOCK_BYTES, rvaToOff);
    }
    if (span.offset >= offset && span.offset + MAX_UNWIND_BLOCK_BYTES <= offset + window.byteLength) {
      return blockAt(span.offset);
    }
    return reader.read(span.offset, span.size).then(view => {
      offset = span.offset;
      window = view;
      return blockAt(offset);
    });
  };
};
