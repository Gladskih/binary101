"use strict";

import type { FileRangeReader } from "../file-range-reader.js";
import type { FileRange } from "./layout/file-ranges.js";
import type { ParsedSecurityDirectory } from "./security/index.js";

const hasCompleteCertificateTable = (
  security: ParsedSecurityDirectory | null | undefined
): security is ParsedSecurityDirectory =>
  !!security && !security.warnings?.length && security.certs.length > 0 &&
  security.certs.every(certificate => certificate.availableBytes === certificate.length);

const validatedCertificateStart = (
  reader: FileRangeReader,
  security: ParsedSecurityDirectory | null | undefined
): number | null => {
  if (!hasCompleteCertificateTable(security)) return null;
  const start = security.certs[0]!.offset;
  // PE/COFF: table entries are quadword-aligned, and zero padding precedes the table.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-attribute-certificate-table-image-only
  return Number.isSafeInteger(start) && start > 0 && start % 8 === 0 && start < reader.size
    ? start : null;
};

export const readPeCertificateAlignmentPadding = async (
  reader: FileRangeReader,
  security: ParsedSecurityDirectory | null | undefined,
  unexplained: FileRange[],
  preceding: FileRange[]
): Promise<FileRange | null> => {
  const certificateStart = validatedCertificateStart(reader, security);
  if (certificateStart == null) return null;
  const range = unexplained.find(candidate => candidate.end === certificateStart);
  // Only the complete gap from a known structure to the next 8-byte boundary qualifies.
  if (!range || range.end - range.start < 1 || range.end - range.start > 7 ||
      !preceding.some(known => known.end === range.start)) return null;
  const padding = await reader.read(range.start, range.end - range.start);
  if (padding.byteLength !== range.end - range.start) return null;
  for (let index = 0; index < padding.byteLength; index++) {
    if (padding.getUint8(index) !== 0) return null;
  }
  return range;
};
