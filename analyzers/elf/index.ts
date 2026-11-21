import { readElfImageHeaders } from "./image-headers.js";
import { selectElfBinaryLayout } from "./binary-layout.js";
import { parseElfMetadata } from "./metadata.js";
import type { ElfParseResult, ElfReport } from "./types.js";

export async function parseElfReport(file: File): Promise<ElfReport | null> {
  const result = await readElfImageHeaders(file);
  if (result && !("incompleteHeader" in result)) {
    const layout = selectElfBinaryLayout(result);
    if (result.header.ehsize >= layout.headerSize) await parseElfMetadata(file, result, layout);
  }
  return result;
}

// Consumers that need an interpretable ELF image receive only complete fixed headers.
export async function parseElf(file: File): Promise<ElfParseResult | null> {
  const result = await parseElfReport(file);
  return result && !("incompleteHeader" in result) ? result : null;
}
