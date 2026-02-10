"use strict";

import type { AddCoverageRegion, PeDataDirectory, RvaToOffset } from "./types.js";

import {
  buildCor20Issues,
  COR20_HEADER_MIN_BYTES,
  COR20_HEADER_SIZE_BYTES,
  readCor20Header
} from "./clr-cor20-header.js";
import { parseClrMetadataRoot } from "./clr-metadata-root.js";
import { parseVTableFixups } from "./clr-vtable-fixups.js";
import type { PeClrHeader } from "./clr-types.js";

export type { PeClrHeader, PeClrMeta, PeClrStreamInfo, PeClrVTableFixup } from "./clr-types.js";

const addOptionalDirIssues = (
  name: string,
  rva: number,
  size: number,
  fileSize: number,
  rvaToOff: RvaToOffset,
  issues: string[]
): void => {
  if (rva === 0 && size === 0) return;
  if (rva === 0 && size !== 0) {
    issues.push(`${name} has a non-zero size but RVA is 0.`);
    return;
  }
  if (rva !== 0 && size === 0) {
    issues.push(`${name} has an RVA but size is 0.`);
    return;
  }
  const off = rvaToOff(rva);
  if (off == null) {
    issues.push(`${name} RVA could not be mapped to a file offset.`);
    return;
  }
  if (off < 0 || off >= fileSize) {
    issues.push(`${name} location is outside the file.`);
    return;
  }
  if (off + size > fileSize) {
    issues.push(`${name} data is truncated; spills past end of file.`);
  }
};

export async function parseClrDirectory(
  file: File,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  addCoverageRegion: AddCoverageRegion
): Promise<PeClrHeader | null> {
  const dir = dataDirs.find(d => d.name === "CLR_RUNTIME");
  if (!dir) return null;
  if (dir.rva === 0 && dir.size === 0) return null;
  const fileSize = file.size;
  const issues: string[] = [];
  if (dir.rva === 0 && dir.size !== 0) issues.push("CLR directory has a non-zero size but RVA is 0.");
  if (dir.rva !== 0 && dir.size === 0) issues.push("CLR directory has an RVA but size is 0.");
  if (dir.rva === 0) {
    const empty = readCor20Header(new DataView(new ArrayBuffer(0)));
    if (issues.length) empty.issues = issues;
    return empty;
  }
  const base = rvaToOff(dir.rva);
  if (base == null) {
    issues.push("CLR directory RVA could not be mapped to a file offset.");
    const empty = readCor20Header(new DataView(new ArrayBuffer(0)));
    if (issues.length) empty.issues = issues;
    return empty;
  }
  if (base < 0 || base >= fileSize) {
    issues.push("CLR directory location is outside the file.");
    const empty = readCor20Header(new DataView(new ArrayBuffer(0)));
    if (issues.length) empty.issues = issues;
    return empty;
  }
  const availableSize = Math.min(dir.size, Math.max(0, fileSize - base));
  if (availableSize > 0) addCoverageRegion("CLR (.NET) header", base, availableSize);
  issues.push(...buildCor20Issues(dir.size, availableSize));
  const clr = readCor20Header(
    new DataView(
      await file
        .slice(base, base + Math.min(availableSize, COR20_HEADER_SIZE_BYTES))
        .arrayBuffer()
    )
  );
  if (clr.cb !== 0 && clr.cb !== COR20_HEADER_SIZE_BYTES) {
    issues.push(`CLR header cb is ${clr.cb} bytes; expected ${COR20_HEADER_SIZE_BYTES} (0x48).`);
  }
  if (clr.cb !== 0 && clr.cb < COR20_HEADER_MIN_BYTES) {
    issues.push("CLR header cb is smaller than the minimum header size (0x18 bytes).");
  }
  if (clr.cb !== 0 && dir.size !== 0 && dir.size < clr.cb) {
    issues.push("CLR directory size is smaller than the header cb field; header appears truncated.");
  }
  if (clr.MetaDataRVA === 0 && clr.MetaDataSize !== 0) {
    issues.push("Metadata has a non-zero size but RVA is 0.");
  }
  if (clr.MetaDataRVA !== 0 && clr.MetaDataSize === 0) {
    issues.push("Metadata has an RVA but size is 0.");
  }
  if (clr.MetaDataRVA !== 0 && clr.MetaDataSize !== 0) {
    const metaOffset = rvaToOff(clr.MetaDataRVA);
    if (metaOffset == null) {
      issues.push("Metadata RVA could not be mapped to a file offset.");
    } else {
      const meta = await parseClrMetadataRoot(file, metaOffset, clr.MetaDataSize, issues);
      if (meta) clr.meta = meta;
    }
  }
  addOptionalDirIssues("Resources", clr.ResourcesRVA, clr.ResourcesSize, fileSize, rvaToOff, issues);
  addOptionalDirIssues(
    "StrongNameSignature",
    clr.StrongNameSignatureRVA,
    clr.StrongNameSignatureSize,
    fileSize,
    rvaToOff,
    issues
  );
  addOptionalDirIssues(
    "CodeManagerTable",
    clr.CodeManagerTableRVA,
    clr.CodeManagerTableSize,
    fileSize,
    rvaToOff,
    issues
  );
  addOptionalDirIssues(
    "ExportAddressTableJumps",
    clr.ExportAddressTableJumpsRVA,
    clr.ExportAddressTableJumpsSize,
    fileSize,
    rvaToOff,
    issues
  );
  addOptionalDirIssues(
    "ManagedNativeHeader",
    clr.ManagedNativeHeaderRVA,
    clr.ManagedNativeHeaderSize,
    fileSize,
    rvaToOff,
    issues
  );
  const fixups = await parseVTableFixups(
    file,
    rvaToOff,
    fileSize,
    clr.VTableFixupsRVA,
    clr.VTableFixupsSize,
    issues
  );
  if (fixups) clr.vtableFixups = fixups;
  if (issues.length) clr.issues = issues;
  return clr;
}
