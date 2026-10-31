import type { FileRangeReader } from "../file-range-reader.js";
import { decompressDwarfZstd } from "../dwarf/zstd.js";
import { previewManagedResourceBytes } from "../pe/clr/managed-resource-preview.js";
import type { EmbeddedResource, ResourceDecodeResult, ResourcePayload } from "./types.js";
import { inspectResource, readResource, requireResource, resourceBytes } from "./reader.js";
import { resolveResourcePayload } from "./payload.js";

const inflateContent = async (bytes: Uint8Array, expected: number): Promise<Uint8Array> => {
  const stream = new Blob([new Uint8Array(bytes)]).stream().pipeThrough(new DecompressionStream("deflate"));
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      size += next.value.length;
      if (size > expected) {
        await reader.cancel();
        throw new Error("Decompressed resource exceeds its declared size");
      }
      chunks.push(next.value);
    }
  } finally {
    reader.releaseLock();
  }
  requireResource(size === expected, "Decompressed resource size mismatch");
  const output = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.length;
  }
  return output;
};

export const readEmbeddedResourceContent = (reader: FileRangeReader, payload: ResourcePayload,
  maxBytes: number): Promise<ResourceDecodeResult<Uint8Array>> => inspectResource(async () => {
  requireResource(Number.isSafeInteger(payload.uncompressedSize) && payload.uncompressedSize >= 0 &&
    payload.uncompressedSize <= maxBytes && payload.size <= maxBytes,
  "Resource content exceeds the configured memory budget");
  const bytes = resourceBytes(await readResource(reader, payload, 0, payload.size));
  if (payload.compression === "zlib") return inflateContent(bytes, payload.uncompressedSize);
  if (payload.compression === "zstd") return decompressDwarfZstd(bytes, payload.uncompressedSize);
  requireResource(bytes.length === payload.uncompressedSize, "Stored resource size mismatch");
  return bytes;
});

export const previewEmbeddedResources = async (reader: FileRangeReader,
  resource: EmbeddedResource, budget: { remainingBytes: number }): Promise<string[]> => {
  const issues: string[] = [];
  const cache = new Map<string, Awaited<ReturnType<typeof previewManagedResourceBytes>>>();
  for (const entry of resource.entries) {
    const payload = resolveResourcePayload(resource.format, entry);
    if (!payload) continue;
    const key = JSON.stringify(payload);
    if (!cache.has(key)) {
      const content = await readEmbeddedResourceContent(reader, payload, budget.remainingBytes);
      if (!content.value) {
        issues.push(`Content at ${payload.offset}: ${content.issues.join("; ")}`);
        cache.set(key, null);
        continue;
      }
      budget.remainingBytes -= content.value.length;
      cache.set(key, await previewManagedResourceBytes(content.value));
    }
    const preview = cache.get(key);
    if (preview) entry.preview = { ...preview.preview, ...(preview.issues ? { previewIssues: preview.issues } : {}) };
  }
  return issues;
};
