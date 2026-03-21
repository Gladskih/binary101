"use strict";

import { decodeWinCertificate, type ParsedWinCertificate } from "./authenticode.js";
import type { AddCoverageRegion, PeDataDirectory } from "./types.js";

export interface ParsedSecurityDirectory {
  count: number;
  certs: ParsedWinCertificate[];
  warnings?: string[];
}

export async function parseSecurityDirectory(
  file: File,
  dataDirs: PeDataDirectory[],
  addCoverageRegion: AddCoverageRegion
): Promise<ParsedSecurityDirectory | null> {
  const dir = dataDirs.find(d => d.name === "SECURITY");
  if (!dir || (dir.rva === 0 && dir.size === 0)) return null;
  const warnings: string[] = [];
  if (!dir.rva) {
    warnings.push("Attribute certificate table has a non-zero size but file offset is 0.");
    return { count: 0, certs: [], warnings };
  }
  const off = dir.rva;
  if (off >= file.size) {
    warnings.push("Attribute certificate table starts past end of file.");
    return { count: 0, certs: [], warnings };
  }
  if ((off & 7) !== 0) {
    warnings.push("Attribute certificate table offset is not quadword aligned.");
  }
  const end = Math.min(file.size, off + dir.size);
  const availableSize = Math.max(0, end - off);
  addCoverageRegion("SECURITY (WIN_CERTIFICATE)", off, availableSize);
  if (availableSize < dir.size) {
    warnings.push("Attribute certificate table is truncated by end of file.");
  }
  if (end < file.size) {
    warnings.push("Attribute certificate table has bytes after the declared table.");
  }
  if (availableSize < 8) {
    warnings.push("Attribute certificate table is too small for a WIN_CERTIFICATE header.");
    return { count: 0, certs: [], warnings };
  }
  let pos = off;
  const certs: ParsedWinCertificate[] = [];
  while (pos + 8 <= end) {
    const head = new DataView(await file.slice(pos, pos + 8).arrayBuffer());
    const Length = head.getUint32(0, true);
    if (Length < 8) {
      warnings.push("WIN_CERTIFICATE length is smaller than the 8-byte header.");
      break;
    }
    if ((Length & 7) !== 0) {
      warnings.push("WIN_CERTIFICATE length is not quadword aligned.");
    }
    const available = Math.min(Length, end - pos);
    const blob = new Uint8Array(await file.slice(pos, pos + available).arrayBuffer());
    certs.push(decodeWinCertificate(blob, Length, pos));
    const roundedLength = (Length + 7) & ~7;
    if (pos + roundedLength > end) {
      warnings.push("WIN_CERTIFICATE data is truncated before the rounded entry length ends.");
    }
    pos += roundedLength;
  }
  if (pos !== end) {
    warnings.push("Attribute certificate table appears corrupt; rounded certificate lengths do not match the declared size.");
  }
  return warnings.length ? { count: certs.length, certs, warnings } : { count: certs.length, certs };
}

