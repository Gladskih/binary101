"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import { loadIcedX86 } from "#iced-x86-loader";
import type {
  AnalyzePeEntrypointDisassemblyOptions,
  PeEntrypointDisassemblyReport
} from "./types.js";
import {
  emptyReport,
  validateMetadata
} from "./entrypoint/metadata.js";
import { loadCodeBytes, type MappedCodeBlock } from "./entrypoint/code-bytes.js";
import { decodePreview } from "./entrypoint/preview.js";
import { isIcedModule } from "./entrypoint/iced.js";

type IcedLoader = () => Promise<unknown>;

export async function analyzePeEntrypointDisassembly(
  reader: FileRangeReader,
  opts: AnalyzePeEntrypointDisassemblyOptions,
  loader: IcedLoader = loadIcedX86
): Promise<PeEntrypointDisassemblyReport> {
  const issues: string[] = [];
  const metadata = validateMetadata(opts, issues);
  if (!metadata) return emptyReport(opts, issues);
  let mapped: MappedCodeBlock | null;
  try {
    mapped = await loadCodeBytes(reader, opts, metadata.entrypointRva, issues, "Entry point");
  } catch (error) {
    issues.push(`Entrypoint byte loading failed (${String(error)})`);
    return emptyReport(opts, issues);
  }
  if (!mapped) return emptyReport(opts, issues);
  if (mapped.data.length === 0) {
    issues.push("No file bytes are available at the mapped entry point.");
    return emptyReport(opts, issues);
  }
  let loaded: unknown;
  try {
    loaded = await loader();
  } catch (error) {
    issues.push(`Failed to load iced-x86 disassembler (${String(error)})`);
    return emptyReport(opts, issues);
  }
  if (!isIcedModule(loaded)) {
    issues.push("Failed to load iced-x86 disassembler (unexpected module shape).");
    return emptyReport(opts, issues);
  }
  try {
    return {
      bitness: metadata.bitness,
      entrypointRva: metadata.entrypointRva,
      ...(await decodePreview(reader, loaded, opts, metadata, mapped, issues)),
      issues
    };
  } catch (error) {
    issues.push(`Entrypoint disassembly failed (${String(error)})`);
    return emptyReport(opts, issues);
  }
}
