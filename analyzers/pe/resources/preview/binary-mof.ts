"use strict";

import { parseBinaryMofClasses } from "./mof-classes.js";
import { decompressMofDs01 } from "./mof-ds.js";
import type { ResourcePreviewResult } from "./types.js";

// bmfdec.c documents both FOMB headers and BMOFQUALFLAVOR11 trailer.
// https://github.com/pali/bmfdec/blob/master/bmfdec.c#L226-L241
const hasText = (bytes: Uint8Array, offset: number, text: string): boolean =>
  [...text].every((char, index) => bytes[offset + index] === char.charCodeAt(0));

const readFlavorCount = (
  bytes: Uint8Array, view: DataView, firstPartEnd: number, issues: string[]
): number => {
  if (firstPartEnd === bytes.length) return 0;
  if (!hasText(bytes, firstPartEnd, "BMOFQUALFLAVOR11") ||
    firstPartEnd + 20 > bytes.length) {
    issues.push("Binary MOF qualifier-flavor trailer is invalid or truncated.");
    return 0;
  }
  const count = view.getUint32(firstPartEnd + 16, true);
  if (count * 8 !== bytes.length - firstPartEnd - 20) {
    issues.push("Binary MOF qualifier-flavor records are truncated or inconsistent.");
    return 0;
  }
  return count;
};

export const addBinaryMofPreview = (
  bytes: Uint8Array, typeName: string
): ResourcePreviewResult | null => {
  if (!["MOFDATA", "FOMB", "BMOF"].includes(typeName)) return null;
  const issues: string[] = [];
  const summary: ResourcePreviewResult["preview"] = { previewKind: "summary", previewFields: [
    { label: "Type", value: typeName }, { label: "Format", value: "Binary WMI MOF" }
  ] };
  if (bytes.length < 16 || !hasText(bytes, 0, "FOMB")) {
    return { preview: summary, issues: ["Binary MOF FOMB header is invalid or truncated."] };
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.length);
  if (view.getUint32(4, true) !== 1) {
    return { preview: summary, issues: ["Binary MOF FOMB version is unsupported."] };
  }
  const compressedSize = view.getUint32(8, true);
  if (compressedSize !== bytes.length - 16) {
    issues.push("Binary MOF compressed size differs from resource size.");
  }
  if (compressedSize > bytes.length - 16) return { preview: summary, issues };
  const output = decompressMofDs01(bytes.subarray(16, 16 + compressedSize),
    view.getUint32(12, true), issues);
  if (!output) return { preview: summary, issues };
  if (output.length < 20 || !hasText(output, 0, "FOMB")) {
    issues.push("Binary MOF decompressed FOMB header is invalid.");
    return { preview: summary, issues };
  }
  const inner = new DataView(output.buffer, output.byteOffset, output.length);
  const firstPartEnd = inner.getUint32(4, true);
  if (firstPartEnd < 20 || firstPartEnd > output.length) {
    issues.push("Binary MOF class section size is invalid.");
    return { preview: summary, issues };
  }
  const flavorCount = readFlavorCount(output, inner, firstPartEnd, issues);
  const classes = parseBinaryMofClasses(output, firstPartEnd, issues);
  return { preview: { previewKind: "binaryMof", binaryMof: { classes, flavorCount } },
    ...(issues.length ? { issues } : {}) };
};
