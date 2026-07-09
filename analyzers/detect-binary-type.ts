"use strict";

import { detectPdfVersion, hasZipEocdSignature, refineCompoundLabel, refineZipLabel } from "./detection-labels.js";
import { DEFAULT_FILE_READ_WINDOW_BYTES } from "./file-range-reader.js";
import { probeElf } from "./elf/probe.js";
import { probeMachO } from "./macho/probe.js";
import { probeMp3 } from "./mp3/index.js";
import { probeMzFormat, type MzProbeResult } from "./mz-probe.js";
import { buildCoffObjectLabel, probeCoffObject } from "./coff/probe.js";
import { mapMachine } from "./pe/security/signature.js";
import { probeByMagic, probeTextLike } from "./probes.js";
import { hasTgaFooterSignature } from "./tga/footer.js";
import { isTgaFileName } from "./tga/index.js";
import { TGA_HEADER_SIZE } from "./tga/tga-parsing.js";
import { detectVirtualHardDisk } from "./vhd/probe.js";

const readSliceView = async (file: File, start: number, end: number): Promise<DataView> => {
  const safeStart = Math.max(0, Math.min(Math.trunc(start), file.size));
  const safeEnd = Math.max(safeStart, Math.min(Math.trunc(end), file.size));
  return new DataView(await file.slice(safeStart, safeEnd).arrayBuffer());
};

const readProbeView = async (file: File): Promise<DataView> =>
  readSliceView(file, 0, Math.min(file.size, DEFAULT_FILE_READ_WINDOW_BYTES));

const buildPeLabel = async (file: File, mz: MzProbeResult): Promise<string> => {
  const peHeaderOffset = mz.eLfanew >>> 0;
  const coffHeaderOffset = peHeaderOffset + 4;
  const coffHeader = await readSliceView(file, coffHeaderOffset, coffHeaderOffset + 20);
  if (coffHeader.byteLength < 20) return "PE executable (truncated COFF header)";
  const machine = coffHeader.getUint16(0, true);
  const characteristics = coffHeader.getUint16(18, true);
  const magicView = await readSliceView(file, coffHeaderOffset + 20, coffHeaderOffset + 22);
  if (magicView.byteLength < 2) {
    return `PE executable for ${mapMachine(machine)} (truncated optional header)`;
  }
  const optionalHeaderMagic = magicView.getUint16(0, true);
  // PE optional-header magic values are defined by Microsoft PE/COFF "Optional Header".
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-image-only
  if (optionalHeaderMagic === 0x107) return `PE ROM image for ${mapMachine(machine)}`;
  const peKind = optionalHeaderMagic === 0x20b ? "PE32+" : "PE32";
  const fileKind = (characteristics & 0x2000) !== 0 ? "DLL" : "executable";
  return `${peKind} ${fileKind} for ${mapMachine(machine)}`;
};

const buildMzLabel = async (file: File, dv: DataView): Promise<string | null> => {
  const mz = await probeMzFormat(file, dv);
  if (!mz) return null;
  if (mz.kind === "pe") return buildPeLabel(file, mz);
  if (mz.kind === "ne") return "NE executable (16-bit Windows/OS/2)";
  if (mz.kind === "le" || mz.kind === "lx") return "Linear executable (LX/LE)";
  return "MS-DOS MZ executable";
};

const refineMagicLabel = (dv: DataView, magic: string): string => {
  if (magic.startsWith("ZIP archive")) return refineZipLabel(dv) || "ZIP archive";
  if (magic === "PDF document") {
    const version = detectPdfVersion(dv);
    return version ? `PDF document (v${version})` : magic;
  }
  if (magic.startsWith("Microsoft Compound File")) return refineCompoundLabel(dv) || magic;
  return magic;
};

const buildTgaHeaderLabel = (dv: DataView): string => {
  if (dv.byteLength < TGA_HEADER_SIZE) return "TGA image";
  // Source: Truevision TGA File Format Specification v2.0, "Image Header".
  const imageType = dv.getUint8(2);
  const width = dv.getUint16(12, true);
  const height = dv.getUint16(14, true);
  const pixelDepth = dv.getUint8(16);
  const parts: string[] = [];
  if (width && height) parts.push(`${width}x${height}`);
  if (pixelDepth) parts.push(`${pixelDepth}-bit`);
  if (imageType === 9 || imageType === 10 || imageType === 11) parts.push("RLE");
  return parts.length ? `TGA image (${parts.join(", ")})` : "TGA image";
};

const detectTga = async (file: File, dv: DataView): Promise<string | null> => {
  if (!isTgaFileName(file.name) && !(await hasTgaFooterSignature(file))) return null;
  return buildTgaHeaderLabel(dv);
};

const detectBinaryType = async (file: File): Promise<string> => {
  if (file.size === 0) return "Empty file";
  const dv = await readProbeView(file);
  const elf = probeElf(dv);
  if (elf) return elf;
  const macho = probeMachO(dv, file.size);
  if (macho) return macho;
  const mzLabel = await buildMzLabel(file, dv);
  if (mzLabel) return mzLabel;
  const coffObject = probeCoffObject(dv, file.size);
  if (coffObject) return buildCoffObjectLabel(coffObject);
  const magic = probeByMagic(dv);
  if (magic) return refineMagicLabel(dv, magic);
  if (hasZipEocdSignature(dv)) return "ZIP archive";
  const tga = await detectTga(file, dv);
  if (tga) return tga;
  const virtualHardDisk = await detectVirtualHardDisk(file, dv);
  if (virtualHardDisk) return virtualHardDisk;
  const text = probeTextLike(dv);
  if (text) return text;
  const mp3ProbeView = new DataView(dv.buffer, dv.byteOffset, Math.min(dv.byteLength, 16 * 1024));
  if (probeMp3(mp3ProbeView)) return "MPEG audio stream (MP3/AAC)";
  return "Unknown binary type";
};

export { detectBinaryType };
