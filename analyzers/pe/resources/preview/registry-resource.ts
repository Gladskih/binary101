import { DEFAULT_FILE_READ_WINDOW_BYTES } from "../../../file-range-reader.js";
import type { ResourcePayloadReader } from "../payload-reader.js";
import { decodeRegistryTextChunks } from "./registry-text.js";
import { createRegistryPreview } from "./registry.js";
import type { ResourceLangWithPreview, ResourcePreviewResult } from "./types.js";

export type ReadRegistryResource = (entry: ResourceLangWithPreview) => Promise<ResourcePreviewResult>;

// Data RVA occupies 4 octets: 4 * 8 = 32 bits; unsigned maximum = 2^32 - 1 = 0xffffffff.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#resource-data-entry
const validRange = (reader: ResourcePayloadReader, entry: ResourceLangWithPreview): boolean =>
  [reader.size, entry.dataFileOffset, entry.dataRVA, entry.size]
    .every(value => value != null && Number.isSafeInteger(value) && value >= 0) &&
  entry.dataRVA <= 0xffff_ffff;

const readChunk = async (
  reader: ResourcePayloadReader, entry: ResourceLangWithPreview,
  offset: number, size: number, issues: string[]
): Promise<Uint8Array> => {
  try {
    return reader.readResourceBytes
      ? await reader.readResourceBytes(entry.dataRVA + offset, size)
      : await reader.readBytes(entry.dataFileOffset! + offset, size);
  } catch {
    issues.push("Resource bytes could not be read for preview.");
    return new Uint8Array();
  }
};

async function* resourceChunks(
  reader: ResourcePayloadReader, entry: ResourceLangWithPreview, issues: string[]
): AsyncGenerator<Uint8Array> {
  // A mapped resource may span sections; stop at the first unavailable RVA byte.
  // IMAGE_RESOURCE_DATA_ENTRY.OffsetToData is a 32-bit RVA; its range cannot wrap.
  // Exclusive RVA end = 2^32 = 0x100000000; available bytes = exclusive end - start RVA.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#resource-data-entry
  const available = reader.readResourceBytes
    ? 0x1_0000_0000 - entry.dataRVA : Math.max(0, reader.size - entry.dataFileOffset!);
  const extent = Math.min(entry.size, available);
  let consumed = 0;
  while (consumed < extent) {
    // This is an I/O window, not a limit on the amount of analyzed data.
    const size = Math.min(DEFAULT_FILE_READ_WINDOW_BYTES, extent - consumed);
    const data = await readChunk(reader, entry, consumed, size, issues);
    const chunk = data.subarray(0, size);
    consumed += chunk.length;
    yield chunk;
    if (chunk.length < size) break;
  }
  if (consumed < entry.size) {
    issues.push("Resource preview read fewer bytes than the declared data size.");
  }
}

export const readRegistryResource = async (
  reader: ResourcePayloadReader, entry: ResourceLangWithPreview
): Promise<ResourcePreviewResult> => {
  if (entry.dataFileOffset == null || entry.dataFileOffset < 0) {
    return { issues: ["Resource RVA could not be mapped to a file offset."] };
  }
  if (!validRange(reader, entry)) {
    return { issues: ["ATL RGS: invalid resource file/RVA range."] };
  }
  const issues: string[] = [];
  const { text, encoding } = await decodeRegistryTextChunks(
    resourceChunks(reader, entry, issues), entry.codePage ?? 0, issues);
  return createRegistryPreview(text, encoding, issues);
};

export const createRegistryResourceReader = (reader: ResourcePayloadReader): ReadRegistryResource => {
  // Resource IDs/languages can alias one payload. The I/O-count regression test
  // verifies that aliases reuse one decode; cache entries are bounded by file ranges.
  const previews = new Map<string, Promise<ResourcePreviewResult>>();
  return entry => {
    const key = [entry.dataRVA, entry.dataFileOffset, entry.size, entry.codePage]
      .map(value => String(value)).join(":");
    const cached = previews.get(key);
    if (cached) return cached;
    const preview = readRegistryResource(reader, entry);
    previews.set(key, preview);
    return preview;
  };
};
