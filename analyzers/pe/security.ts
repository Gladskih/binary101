"use strict";

import { decodeWinCertificate, type ParsedWinCertificate } from "./authenticode.js";
import type { AddCoverageRegion, PeDataDirectory } from "./types.js";

export interface ParsedSecurityDirectory {
  count: number;
  certs: ParsedWinCertificate[];
}

export async function parseSecurityDirectory(
  file: File,
  dataDirs: PeDataDirectory[],
  addCoverageRegion: AddCoverageRegion
): Promise<ParsedSecurityDirectory | null> {
  const dir = dataDirs.find(d => d.name === "SECURITY");
  if (!dir?.rva || dir.size < 8) return null;
  const off = dir.rva;
  if (off + 8 > file.size) return null;
  addCoverageRegion("SECURITY (WIN_CERTIFICATE)", off, dir.size);
  const end = Math.min(file.size, off + dir.size);
  let pos = off;
  let iterations = 0;
  const certs: ParsedWinCertificate[] = [];
  while (pos + 8 <= end && iterations < 8) {
    const head = new DataView(await file.slice(pos, pos + 8).arrayBuffer());
    const Length = head.getUint32(0, true);
    if (Length < 8) break;
    const available = Math.min(Length, end - pos);
    const blob = new Uint8Array(await file.slice(pos, pos + available).arrayBuffer());
    certs.push(decodeWinCertificate(blob, Length, pos));
    pos += (Length + 7) & ~7;
    iterations++;
  }
  return { count: certs.length, certs };
}

