import type { PeWindowsParseResult } from "../core/parse-result.js";
import { isRvaRangeInsideSizeOfImage } from "../layout/rva-limits.js";
import { isRvaRange } from "../rva-mapping.js";
import type { PeDisassemblySample } from "./sampling.js";
import type { PeUnpackedCode } from "./types.js";

export const collectPeUnpackedCode = (pe: PeWindowsParseResult | null): {
  imageBase: bigint;
  code: PeUnpackedCode;
} | null => {
  const finding = pe?.packers?.reports.find(report => report.id === "crinkler")
    ?.findings.find(candidate => candidate.id === "crinkler");
  if (!finding?.decoded || finding.layout.profile !== "tiny") return null;
  const { data } = finding.decoded;
  // DepackInit pushes _UnpackedData and RET transfers control to that exact address.
  // https://github.com/runestubbe/Crinkler/blob/f74d964/source/Crinkler/modules/header22_1k.asm
  const { imageBase, unpackedVa, imageSize } = finding.layout;
  const rvaStart = unpackedVa - imageBase;
  if (data.length !== finding.tiny?.size ||
      !isRvaRangeInsideSizeOfImage(rvaStart, data.length, imageSize)) return null;
  return { imageBase: BigInt(imageBase), code: { name: finding.name, rvaStart, data } };
};

export const selectPeUnpackedCode = (
  unpacked: PeUnpackedCode | undefined, fileSamples: PeDisassemblySample[], issues: string[]
): PeUnpackedCode | undefined => {
  if (!unpacked) return;
  const { rvaStart, data, name } = unpacked;
  if (!isRvaRange(rvaStart, data.length)) {
    issues.push(`${name} unpacked code is outside the 32-bit RVA range.`);
    return;
  }
  if (fileSamples.some(sample => sample.rvaStart < rvaStart + data.length &&
      rvaStart < sample.rvaStart + sample.data.length)) {
    issues.push(`${name} unpacked code overlaps sampled file bytes.`);
    return;
  }
  return unpacked;
};
