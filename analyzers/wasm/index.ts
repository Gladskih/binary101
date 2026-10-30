import { WasmStream } from "./stream.js";
import { WasmReader } from "./reader.js";
import type { WasmParseResult, WasmSection } from "./types.js";
import { parseDeclarations } from "./declarations.js";
import { parseSegments } from "./segments.js";
import { parseCustom } from "./custom.js";
import { validateReferences } from "./validation.js";

const createResult = (fileSize: number): WasmParseResult => ({
  fileSize, version: null, sections: [], types: [], imports: [], functions: [], tables: [],
  memories: [], globals: [], exports: [], start: null, elements: [], code: [], data: [],
  dataCount: null, tags: [], moduleName: null, functionNames: {}, producers: [], features: [], issues: []
});

// Core order is not numeric: tags precede globals and data-count precedes code.
// https://webassembly.github.io/spec/core/binary/modules.html#binary-module
const SECTION_ORDER = [1, 2, 3, 4, 5, 13, 6, 7, 8, 9, 12, 10, 11];

const parsePayload = async (reader: WasmReader, section: WasmSection,
  result: WasmParseResult): Promise<void> => {
  if (section.id === 0) await parseCustom(reader, section, result);
  else if ([9, 10, 11].includes(section.id)) await parseSegments(section.id, reader, result);
  else await parseDeclarations(section.id, reader, result);
  reader.finish();
};

const decodeSection = async (payload: WasmReader, section: WasmSection,
  result: WasmParseResult): Promise<void> => {
  try {
    await parsePayload(payload, section, result);
    section.status = section.id === 0 && !["name", "producers", "target_features"].includes(
      section.customName ?? "") ? "opaque" : "decoded";
  } catch (error) {
    section.status = "partial";
    result.issues.push(`Section ${section.id} at ${section.offset}: ${String(error)}`);
  }
};

const checkSectionOrder = (section: WasmSection, seen: Set<number>, previous: number,
  result: WasmParseResult): void => {
  if (section.id === 0) return;
  const order = SECTION_ORDER.indexOf(section.id);
  if (order < previous) result.issues.push(`Section ${section.id} is out of order at ${section.offset}`);
  if (seen.has(section.id)) result.issues.push(`Duplicate section ${section.id} at ${section.offset}`);
  if (order < 0) result.issues.push(`Unknown section ${section.id} at ${section.offset}`);
};

const scanSections = async (reader: WasmReader, result: WasmParseResult): Promise<void> => {
  const seen = new Set<number>();
  let previous = -1;
  while (reader.remaining) {
    const offset = reader.offset;
    const id = await reader.byte();
    const size = await reader.u32();
    const section: WasmSection = { id, offset, payloadOffset: reader.offset, size, status: "opaque" };
    result.sections.push(section);
    const payload = reader.child(size);
    const order = SECTION_ORDER.indexOf(id);
    checkSectionOrder(section, seen, previous, result);
    if (id === 0 || (order >= 0 && !seen.has(id))) {
      await decodeSection(payload, section, result);
    }
    await payload.skip(payload.remaining);
    if (id !== 0) { seen.add(id); previous = Math.max(previous, order); }
  }
};

const readHeader = async (reader: WasmReader, result: WasmParseResult):
  Promise<"foreign" | "unsupported" | "core"> => {
  const magic = await reader.take(4);
  if (!magic.every((byte, index) => byte === [0, 97, 115, 109][index])) return "foreign";
  if (reader.remaining < 4) {
    result.issues.push("WebAssembly header is truncated");
    return "unsupported";
  }
  const version = await reader.take(4);
  result.version = new DataView(version.buffer, version.byteOffset, 4).getUint32(0, true);
  if (result.version === 1) return "core";
  result.issues.push(`Unsupported WebAssembly version ${result.version}; core sections not decoded`);
  return "unsupported";
};

export const parseWasm = async (file: File): Promise<WasmParseResult | null> => {
  if (file.size < 4) return null;
  const source = file.stream().getReader();
  const reader = new WasmReader(new WasmStream(source, file.size));
  const result = createResult(file.size);
  try {
    const header = await readHeader(reader, result);
    if (header === "foreign") return null;
    if (header === "unsupported") return result;
    await scanSections(reader, result);
    validateReferences(result);
  } catch (error) { result.issues.push(`WebAssembly file is truncated or malformed: ${String(error)}`); }
  finally {
    try { await source.cancel(); }
    catch (error) { result.issues.push(`Stream cleanup: ${String(error)}`); }
    source.releaseLock();
  }
  return result;
};
