import type { FileRangeReader } from "../../file-range-reader.js";
import { readCrinklerLayout, readCrinklerTinyLayout, type CrinklerLayout } from "./crinkler-layout.js";
import { readCrinklerModelParts } from "./crinkler-models.js";
import { CRINKLER_TINY_OUTPUT_LIMIT, decodeCrinklerTiny } from "./crinkler-tiny-codec.js";
import { readCrinklerTinyImport } from "./crinkler-tiny-import.js";
import type { PeCrinklerPackerFinding, PePackerDetectorResult } from "./types.js";

type CrinklerDetails = Pick<PeCrinklerPackerFinding, "tiny" | "decoded" | "parts">;

const readTinyDetails = async (
  reader: FileRangeReader, bytes: Uint8Array, layout: CrinklerLayout, warnings: string[]
): Promise<CrinklerDetails> => {
  const tiny = readCrinklerTinyLayout(bytes, layout);
  if (!tiny) {
    warnings.push("Tiny Header decompressor parameters could not be validated.");
    return {};
  }
  if (tiny.size > CRINKLER_TINY_OUTPUT_LIMIT) {
    warnings.push(`Tiny Header output exceeds the ${CRINKLER_TINY_OUTPUT_LIMIT}-byte decode limit.`);
    return { tiny };
  }
  if (layout.streamOffset >= reader.size) return { tiny };
  // Limit the source window independently of the file size. A 32 KiB input window
  // accommodates streams larger than the decoded image while bounding reads.
  const input = await reader.readBytes(layout.streamOffset, 32 * 1024);
  const decoded = decodeCrinklerTiny(input, tiny.size, tiny.model);
  if (decoded) {
    const imports = readCrinklerTinyImport(decoded.data);
    return { tiny, decoded: imports ? { ...decoded, imports } : decoded };
  }
  warnings.push("Tiny Header stream did not produce a verified decode.");
  return { tiny };
};

const readModelDetails = (
  bytes: Uint8Array, layout: CrinklerLayout, warnings: string[]
): CrinklerDetails => {
  const { modelOffset, streamOffset, unpackedVa, version } = layout;
  if (modelOffset != null && streamOffset <= bytes.length) {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const parts = readCrinklerModelParts(view, modelOffset, streamOffset, unpackedVa, version);
    if (parts) return { parts };
  }
  warnings.push("Crinkler part records could not be validated against the packed data offset.");
  return {};
};

export const detectCrinkler = async (
  reader: FileRangeReader
): Promise<PePackerDetectorResult<PeCrinklerPackerFinding>> => {
  // The upstream recompressor searches the first 0x200 bytes for header operands.
  // https://github.com/runestubbe/Crinkler/blob/f74d964/source/Crinkler/Crinkler.cpp
  const bytes = await reader.readBytes(0, 0x200);
  const layout = readCrinklerLayout(bytes);
  if (!layout) return { findings: [], warnings: [] };
  const warnings: string[] = [];
  if (layout.streamOffset >= reader.size) {
    warnings.push("The packed data offset is at or beyond the end of the file.");
  }
  const details = layout.profile === "tiny" ? await readTinyDetails(reader, bytes, layout, warnings)
    : readModelDetails(bytes, layout, warnings);
  return {
    findings: [{
      id: "crinkler", name: "Crinkler", kind: "executable-packer", confidence: "high",
      evidence: [
        "Crinkler version marker agrees with the x86 PE header layout.",
        "The entry stub and the packed stream address match the Crinkler template."
      ],
      layout, ...details
    }],
    warnings
  };
};
