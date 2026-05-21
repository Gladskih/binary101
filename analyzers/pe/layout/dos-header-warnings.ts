"use strict";

import type { PeDosHeader } from "../types.js";

// MS-DOS EXE header: the fixed header is 28 bytes and relocation entries are 4 bytes.
// The PE IMAGE_DOS_HEADER layout extends this to 64 bytes so e_lfanew can live at 0x3c.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#ms-dos-stub-image-only
const DOS_FIXED_HEADER_BYTES = 0x40;
const DOS_FIXED_EXE_HEADER_BYTES = 0x1c;
const DOS_HEADER_PARAGRAPH_BYTES = 16;
const DOS_PAGE_BYTES = 512;
const DOS_RELOCATION_ENTRY_BYTES = 4;
const MIN_PE_DOS_HEADER_PARAGRAPHS = 4;

const formatHex = (value: number): string => `0x${Math.max(0, Math.trunc(value)).toString(16)}`;

const validU16 = (value: number): number | null =>
  Number.isSafeInteger(value) && value >= 0 && value <= 0xffff ? value : null;

const safeAdd = (left: number, right: number): number | null => {
  const value = left + right;
  return Number.isSafeInteger(value) && value >= 0 ? value : null;
};

const computeMzDeclaredSize = (e_cp: number, e_cblp: number): number | null => {
  const pages = validU16(e_cp);
  const lastPageBytes = validU16(e_cblp);
  if (pages == null || lastPageBytes == null || pages === 0 || lastPageBytes > DOS_PAGE_BYTES) return null;
  if (lastPageBytes === 0) return pages * DOS_PAGE_BYTES;
  return (pages - 1) * DOS_PAGE_BYTES + lastPageBytes;
};

const addHeaderSpanWarnings = (dos: PeDosHeader, warnings: string[]): number | null => {
  const paragraphs = validU16(dos.e_cparhdr);
  if (paragraphs == null) return null;
  const headerBytes = paragraphs * DOS_HEADER_PARAGRAPH_BYTES;
  if (paragraphs < MIN_PE_DOS_HEADER_PARAGRAPHS) {
    warnings.push(
      `DOS header size e_cparhdr ${paragraphs} paragraph(s) is smaller than the fixed ` +
        `${MIN_PE_DOS_HEADER_PARAGRAPHS}-paragraph IMAGE_DOS_HEADER; DOS stub entrypoint fields may be unreliable.`
    );
  }
  if (headerBytes > dos.e_lfanew) {
    warnings.push(
      `DOS header size ${formatHex(headerBytes)} extends past PE header offset e_lfanew ` +
        `${formatHex(dos.e_lfanew)}.`
    );
  }
  return headerBytes;
};

const addRelocationWarnings = (dos: PeDosHeader, headerBytes: number | null, warnings: string[]): void => {
  const relocationCount = validU16(dos.e_crlc);
  const relocationTableOffset = validU16(dos.e_lfarlc);
  if (relocationCount == null || relocationTableOffset == null || relocationCount === 0) return;
  if (relocationTableOffset < DOS_FIXED_EXE_HEADER_BYTES) {
    warnings.push(
      `DOS relocation table offset e_lfarlc ${formatHex(relocationTableOffset)} points inside the fixed MZ header.`
    );
  }
  const relocationTableBytes = relocationCount * DOS_RELOCATION_ENTRY_BYTES;
  const relocationTableEnd = safeAdd(relocationTableOffset, relocationTableBytes);
  if (relocationTableEnd == null) return;
  if (headerBytes != null && relocationTableEnd > headerBytes) {
    warnings.push(
      `DOS relocation table ends at ${formatHex(relocationTableEnd)}, beyond declared DOS header size ` +
        `${formatHex(headerBytes)}.`
    );
  }
  if (relocationTableEnd > dos.e_lfanew) {
    warnings.push(
      `DOS relocation table ends at ${formatHex(relocationTableEnd)}, beyond PE header offset e_lfanew ` +
        `${formatHex(dos.e_lfanew)}.`
    );
  }
};

const addEntrypointWarnings = (dos: PeDosHeader, headerBytes: number | null, warnings: string[]): void => {
  const codeSegment = validU16(dos.e_cs);
  const instructionPointer = validU16(dos.e_ip);
  if (headerBytes == null || headerBytes < DOS_FIXED_HEADER_BYTES) return;
  if (codeSegment == null || instructionPointer == null) return;
  const loadModuleOffset = codeSegment * DOS_HEADER_PARAGRAPH_BYTES + instructionPointer;
  const entryFileOffset = safeAdd(headerBytes, loadModuleOffset);
  if (entryFileOffset != null && entryFileOffset >= dos.e_lfanew) {
    warnings.push(
      `DOS entrypoint CS:IP resolves to ${formatHex(entryFileOffset)}, outside the DOS stub bytes before ` +
        `e_lfanew ${formatHex(dos.e_lfanew)}.`
    );
  }
};

const addDeclaredSizeWarnings = (dos: PeDosHeader, headerBytes: number | null, warnings: string[]): void => {
  if (dos.e_cblp > DOS_PAGE_BYTES) {
    warnings.push(`DOS e_cblp ${dos.e_cblp} exceeds the ${DOS_PAGE_BYTES}-byte page size.`);
  }
  if (dos.e_cp === 0) {
    warnings.push("DOS e_cp is zero, so the MZ-declared file size is not meaningful.");
    return;
  }
  const declaredSize = computeMzDeclaredSize(dos.e_cp, dos.e_cblp);
  if (declaredSize == null) return;
  if (headerBytes != null && declaredSize < headerBytes) {
    warnings.push(
      `MZ-declared file size ${formatHex(declaredSize)} is smaller than declared DOS header size ` +
        `${formatHex(headerBytes)}.`
    );
  }
};

export const collectPeDosHeaderWarnings = (dos: PeDosHeader): string[] => {
  const warnings: string[] = [];
  const headerBytes = addHeaderSpanWarnings(dos, warnings);
  addRelocationWarnings(dos, headerBytes, warnings);
  addEntrypointWarnings(dos, headerBytes, warnings);
  addDeclaredSizeWarnings(dos, headerBytes, warnings);
  if (dos.e_maxalloc !== 0 && dos.e_minalloc > dos.e_maxalloc) {
    warnings.push(`DOS e_minalloc ${dos.e_minalloc} is greater than e_maxalloc ${dos.e_maxalloc}.`);
  }
  return warnings;
};
