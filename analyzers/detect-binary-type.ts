"use strict";

import { probeByMagic, probeTextLike } from "./probes.js";
import { parsePe } from "./pe/index.js";
import { mapMachine } from "./pe/signature.js";
import { parsePng } from "./png/index.js";
import { parseWebp } from "./webp/index.js";
import { parseWebm, buildWebmLabel } from "./webm/index.js";
import { parseMp3, probeMp3 } from "./mp3/index.js";
import { parseSevenZip } from "./sevenz/index.js";
import { parseRar } from "./rar/index.js";
import { parseMp4, buildMp4Label } from "./mp4/index.js";
import { detectELF, detectMachO } from "./format-detectors.js";
import {
  detectPdfVersion,
  hasZipEocdSignature,
  refineCompoundLabel,
  refineZipLabel
} from "./detection-labels.js";
import { buildMp3Label } from "./mp3-labels.js";
import { probeMzFormat } from "./mz-probe.js";
import type { Mp3ParseResult } from "./mp3/types.js";

const detectBinaryType = async (file: File): Promise<string> => {
  const maxProbeBytes = Math.min(file.size || 0, 65536);
  const dv = new DataView(
    await file.slice(0, Math.min(file.size, maxProbeBytes)).arrayBuffer()
  );
  const elf = detectELF(dv);
  if (elf) return elf;
  const macho = detectMachO(dv);
  if (macho) return macho;
  const magic = probeByMagic(dv);
  if (magic) {
    if (magic.indexOf("MPEG audio") !== -1) {
      const mp3: Mp3ParseResult = await parseMp3(file);
      const label = buildMp3Label(mp3);
      if (label) return label;
      return "Unknown binary type";
    }
    if (
      magic.indexOf("MP4/QuickTime") !== -1 ||
      (magic.indexOf("ISO-BMFF") !== -1 && magic.indexOf("HEIF") === -1 && magic.indexOf("HEIC") === -1) ||
      magic.indexOf("3GP") !== -1
    ) {
      const brand = dv.byteLength >= 12 ? dv.getUint32(8, false) : 0;
      if (brand !== 0x68656963 && brand !== 0x68656978 && brand !== 0x68657663) {
        const mp4 = await parseMp4(file);
        const label = buildMp4Label(mp4);
        if (label) return label;
        return magic;
      }
    }
    if (magic.startsWith("ZIP archive")) {
      const zipLabel = refineZipLabel(dv);
      if (zipLabel) return zipLabel;
    }
    if (magic === "PDF document") {
      const version = detectPdfVersion(dv);
      if (version) return `PDF document (v${version})`;
    }
    if (magic === "Matroska/WebM container") {
      const webm = await parseWebm(file);
      const label = buildWebmLabel(webm);
      if (label) return label;
      return magic;
    }
    if (magic === "7z archive") {
      const sevenZip = await parseSevenZip(file);
      if (sevenZip?.is7z) {
        const version = sevenZip.startHeader
          ? `${sevenZip.startHeader.versionMajor}.${sevenZip.startHeader.versionMinor}`
          : null;
        const files = sevenZip.structure?.files?.length;
        const extras: string[] = [];
        if (typeof files === "number" && files > 0) extras.push(`${files} file${files === 1 ? "" : "s"}`);
        const suffix = extras.length ? ` (${extras.join(", ")})` : "";
        if (version) return `7z archive v${version}${suffix}`;
        return `7z archive${suffix}`;
      }
      return "7z archive";
    }
    if (magic === "PNG image") {
      const png = await parsePng(file);
      if (png && png.ihdr) {
        const dimensions =
          png.ihdr.width && png.ihdr.height
            ? `${png.ihdr.width}x${png.ihdr.height}`
            : null;
        const color = png.ihdr.colorName || null;
        const extras: string[] = [];
        if (dimensions) extras.push(dimensions);
        if (color) extras.push(color);
        if (png.hasTransparency) extras.push("alpha");
        const suffix = extras.length ? ` (${extras.join(", ")})` : "";
        return `PNG image${suffix}`;
      }
    }
    if (magic === "WebP image") {
      const webp = await parseWebp(file);
      if (webp) {
        const extras: string[] = [];
        if (webp.dimensions && webp.dimensions.width && webp.dimensions.height) {
          extras.push(`${webp.dimensions.width}x${webp.dimensions.height}`);
        }
        if (webp.format === "VP8L") extras.push("lossless");
        else if (webp.format === "VP8") extras.push("lossy");
        else if (webp.format === "VP8X") extras.push("extended");
        if (webp.hasAlpha) extras.push("alpha");
        if (webp.hasAnimation) extras.push("animation");
        const suffix = extras.length ? ` (${extras.join(", ")})` : "";
        return `WebP image${suffix}`;
      }
    }
    if (magic === "RAR archive") {
      const rar = await parseRar(file);
      if (rar?.isRar) {
        const extras: string[] = [];
        extras.push(`v${rar.version}`);
        const count = rar.entries?.length || 0;
        if (count) extras.push(`${count} file${count === 1 ? "" : "s"}`);
        if (rar.mainHeader?.isSolid) extras.push("solid");
        if (rar.mainHeader?.isVolume) extras.push("volume");
        const suffix = extras.length ? ` (${extras.join(", ")})` : "";
        return `RAR archive${suffix}`;
      }
      return "RAR archive";
    }
    if (magic.startsWith("Microsoft Compound File")) {
      const compound = refineCompoundLabel(dv);
      if (compound) return compound;
    }
    return magic;
  }

  if (hasZipEocdSignature(dv)) return "ZIP archive";

  const mzKind = await probeMzFormat(file, dv);
  if (mzKind) {
    if (mzKind.kind === "pe") {
      const pe = await parsePe(file);
      if (pe) {
        const sig = pe.opt.isPlus ? "PE32+" : "PE32";
        const isDll = (pe.coff.Characteristics & 0x2000) !== 0 ? "DLL" : "executable";
        return `${sig} ${isDll} for ${mapMachine(pe.coff.Machine)}`;
      }
      return "PE (unreadable)";
    }
    if (mzKind.kind === "ne") return "NE executable (16-bit Windows/OS/2)";
    if (mzKind.kind === "le" || mzKind.kind === "lx") return "Linear executable (LX/LE)";
    return "MS-DOS MZ executable";
  }
  const text = probeTextLike(dv);
  if (text) return text;

  const mp3ProbeView = new DataView(dv.buffer, dv.byteOffset, Math.min(dv.byteLength, 16384));
  if (probeMp3(mp3ProbeView)) {
    const mp3: Mp3ParseResult = await parseMp3(file);
    const label = buildMp3Label(mp3);
    if (label) return label;
  }
  return "Unknown binary type";
};

export { detectBinaryType };
