"use strict";

import type { ProbeResult } from "../probes/probe-types.js";

// MS-VHDX 2.1: the file identifier signature is ASCII "vhdxfile".
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-vhdx/83e061f8-f6e2-4de1-91bd-5d518a43d477
const VHDX_FILE_IDENTIFIER_SIGNATURE = "vhdxfile";
// Microsoft VHD Image Format Specification, "Hard Disk Footer": current VHD
// footers are 512 bytes; older images may use a 511-byte footer.
const CURRENT_VHD_FOOTER_BYTE_LENGTH = 512;
const LEGACY_VHD_FOOTER_BYTE_LENGTH = 511;
const VHD_FOOTER_BYTE_LENGTHS = [
  CURRENT_VHD_FOOTER_BYTE_LENGTH,
  LEGACY_VHD_FOOTER_BYTE_LENGTH
] as const;
const VHD_FOOTER_COOKIE = "conectix";

const hasAsciiAt = (view: DataView, offset: number, text: string): boolean => {
  if (offset < 0 || offset + text.length > view.byteLength) return false;
  for (let index = 0; index < text.length; index += 1) {
    if (view.getUint8(offset + index) !== text.charCodeAt(index)) return false;
  }
  return true;
};

const detectVhdxHeader = (view: DataView): ProbeResult =>
  hasAsciiAt(view, 0, VHDX_FILE_IDENTIFIER_SIGNATURE)
    ? "Virtual Hard Disk v2 image (VHDX)"
    : null;

const detectVhdFooter = (view: DataView): ProbeResult => {
  const footerOffsets = [
    0,
    ...VHD_FOOTER_BYTE_LENGTHS.map(footerByteLength => view.byteLength - footerByteLength)
  ];
  for (const offset of footerOffsets) {
    if (offset < 0 || offset + LEGACY_VHD_FOOTER_BYTE_LENGTH > view.byteLength) continue;
    if (hasAsciiAt(view, offset, VHD_FOOTER_COOKIE)) return "Virtual Hard Disk image (VHD)";
  }
  return null;
};

const detectVirtualHardDiskHeader = (view: DataView): ProbeResult =>
  detectVhdxHeader(view) ?? detectVhdFooter(view);

const detectVirtualHardDisk = async (file: File, headerView: DataView): Promise<ProbeResult> => {
  const headerLabel = detectVirtualHardDiskHeader(headerView);
  if (headerLabel || file.size < LEGACY_VHD_FOOTER_BYTE_LENGTH) return headerLabel;
  const tailSize = Math.min(file.size, CURRENT_VHD_FOOTER_BYTE_LENGTH);
  const tail = new DataView(await file.slice(file.size - tailSize, file.size).arrayBuffer());
  return detectVhdFooter(tail);
};

export { detectVirtualHardDisk, detectVirtualHardDiskHeader };
