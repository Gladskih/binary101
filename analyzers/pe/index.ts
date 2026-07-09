"use strict";
import { createFileRangeReader } from "../file-range-reader.js";
import { isPeWindowsCore, parsePeHeaders } from "./core/index.js";
import {
  parseBrowserManifestXmlDocument,
  type ManifestXmlDocumentParser
} from "./resources/preview/manifest-xml.js";
import { buildHeaderOnlyPeParseResult } from "./core/header-only-result.js";
import { collectPeLayoutWarnings } from "./layout/warnings.js";
import { parseWindowsPe } from "./parse-windows.js";
export {
  isPeRomParseResult,
  isPeWindowsParseResult
} from "./core/parse-result.js";
export type {
  PeDebugSection,
  PeHeaderParseResult,
  PeParseResult,
  PeWindowsParseResult
} from "./core/parse-result.js";
export type { PeLinuxBootProtocol } from "./linux-boot.js";
import type { PeParseResult } from "./core/parse-result.js";

const appendUniqueMessages = (existing: string[] | undefined, messages: string[]): string[] | undefined =>
  messages.length ? [...new Set([...(existing ?? []), ...messages])] : existing;

const withLayoutWarnings = <T extends PeParseResult>(result: T, fileSize: number): T => {
  const mergedWarnings = appendUniqueMessages(result.warnings, collectPeLayoutWarnings(result, fileSize));
  return mergedWarnings?.length ? { ...result, warnings: mergedWarnings } : result;
};

export async function parsePe(
  file: File,
  parseManifestXmlDocument: ManifestXmlDocumentParser = parseBrowserManifestXmlDocument
): Promise<PeParseResult | null> {
  const reader = createFileRangeReader(file, 0, file.size);
  const core = await parsePeHeaders(reader);
  if (!core) return null;
  if (!isPeWindowsCore(core)) {
    return withLayoutWarnings(buildHeaderOnlyPeParseResult(core), file.size);
  }
  return parseWindowsPe(file, reader, core, parseManifestXmlDocument);
}
