import type { EmbeddedResource, EmbeddedResourceEntry, ResourcePayload } from "./types.js";

// Normalize decoding inputs at the consumer boundary. Keep the parsed result's
// raw flags and physical sizes as the single source of truth.
export const resolveResourcePayload = (format: EmbeddedResource["format"],
  entry: EmbeddedResourceEntry): ResourcePayload | null => {
  if (!entry.payload) return null;
  const compression = entry.flags === 0 ? "none" :
    format === "Qt RCC" && entry.flags === 4 ? "zstd" : "zlib";
  return { ...entry.payload, compression,
    uncompressedSize: entry.payload.uncompressedSize ?? entry.payload.size };
};
