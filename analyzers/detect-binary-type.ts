"use strict";

import { probeByMagic, probeTextLike } from "./probes.js";
import { parseCoffHeader } from "./pe/core-headers.js";
import { mapMachine } from "./pe/signature.js";
import { parsePng } from "./png/index.js";
import { parseWebp } from "./webp/index.js";
import { parseWebm, buildWebmLabel } from "./webm/index.js";
import { parseMp3, probeMp3 } from "./mp3/index.js";
import { parseFlac } from "./flac/index.js";
import { parseSevenZip } from "./sevenz/index.js";
import { parseRar } from "./rar/index.js";
import { parseMp4, buildMp4Label } from "./mp4/index.js";
import { parseWav } from "./wav/index.js";
import { parseAvi } from "./avi/index.js";
import { parseAni } from "./ani/index.js";
import { detectELF, detectMachO } from "./format-detectors.js";
import { parseAsf, buildAsfLabel } from "./asf/index.js";
import {
  detectPdfVersion,
  hasZipEocdSignature,
  refineCompoundLabel,
  refineZipLabel
} from "./detection-labels.js";
import { buildMp3Label } from "./mp3-labels.js";
import { probeMzFormat } from "./mz-probe.js";
import type { Mp3ParseResult } from "./mp3/types.js";
import type { WavParseResult } from "./wav/types.js";
import type { AviParseResult } from "./avi/types.js";
import type { AniParseResult } from "./ani/types.js";
import type { FlacParseResult } from "./flac/types.js";
import { buildSqliteLabel, parseSqlite } from "./sqlite/index.js";

const buildWavLabel = (wav: WavParseResult | null): string | null => {
  if (!wav) return null;
  const parts: string[] = [];
  if (wav.format?.formatName) parts.push(wav.format.formatName);
  else if (wav.format?.audioFormat != null) {
    parts.push(`0x${wav.format.audioFormat.toString(16)}`);
  }
  if (wav.format?.channels) parts.push(`${wav.format.channels}ch`);
  if (wav.format?.sampleRate) parts.push(`${wav.format.sampleRate}Hz`);
  if (wav.format?.bitsPerSample) parts.push(`${wav.format.bitsPerSample}-bit`);
  const suffix = parts.length ? ` (${parts.join(", ")})` : "";
  return `WAVE audio${suffix}`;
};

const buildAviLabel = (avi: AviParseResult | null): string | null => {
  if (!avi) return null;
  const parts: string[] = [];
  const main = avi.mainHeader;
  if (main?.width && main?.height) parts.push(`${main.width}x${main.height}`);
  const fps = main?.frameRate;
  if (fps) parts.push(`${fps} fps`);
  const videoStreams = avi.streams.filter(stream => stream.header?.type === "vids").length;
  const audioStreams = avi.streams.filter(stream => stream.header?.type === "auds").length;
  if (videoStreams || audioStreams) {
    parts.push(`${videoStreams} video / ${audioStreams} audio`);
  }
  const suffix = parts.length ? ` (${parts.join(", ")})` : "";
  return `AVI/DivX video${suffix}`;
};

const buildAniLabel = (ani: AniParseResult | null): string | null => {
  if (!ani) return null;
  const parts: string[] = ["ANI"];
  if (ani.header?.width && ani.header?.height) {
    parts.push(`${ani.header.width}x${ani.header.height}`);
  }
  if (ani.header?.frameCount) parts.push(`${ani.header.frameCount} frames`);
  if (ani.header?.defaultFps) parts.push(`${ani.header.defaultFps} fps`);
  return `Windows animated cursor (${parts.join(", ")})`;
};

const buildFlacLabel = (flac: FlacParseResult | null): string | null => {
  if (!flac?.streamInfo) return null;
  const parts: string[] = [];
  const info = flac.streamInfo;
  if (info.channels) parts.push(`${info.channels}ch`);
  if (info.sampleRate) parts.push(`${info.sampleRate}Hz`);
  if (info.bitsPerSample) parts.push(`${info.bitsPerSample}-bit`);
  if (info.durationSeconds) parts.push(`${info.durationSeconds} s`);
  if (info.averageBitrateKbps) parts.push(`${info.averageBitrateKbps} kbps`);
  const suffix = parts.length ? ` (${parts.join(", ")})` : "";
  return `FLAC audio${suffix}`;
};

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
    if (magic.indexOf("WAVE audio") !== -1) {
      const wav = await parseWav(file);
      const label = buildWavLabel(wav);
      if (label) return label;
      return magic;
    }
    if (
      magic.indexOf("MP4/QuickTime") !== -1 ||
      (magic.indexOf("ISO-BMFF") !== -1 &&
        magic.indexOf("HEIF") === -1 &&
        magic.indexOf("HEIC") === -1) ||
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
    if (magic.indexOf("ASF container") !== -1) {
      const asf = await parseAsf(file);
      const label = buildAsfLabel(asf);
      if (label) return label;
      return magic;
    }
    if (magic.indexOf("AVI/DivX video") !== -1) {
      const avi = await parseAvi(file);
      const label = buildAviLabel(avi);
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
        if (typeof files === "number" && files > 0) {
          extras.push(`${files} file${files === 1 ? "" : "s"}`);
        }
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
    if (magic.indexOf("FLAC audio") !== -1) {
      const flac = await parseFlac(file);
      const label = buildFlacLabel(flac);
      if (label) return label;
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
    if (magic.indexOf("Windows animated cursor") !== -1) {
      const ani = await parseAni(file);
      const label = buildAniLabel(ani);
      if (label) return label;
      return magic;
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
    if (magic.indexOf("SQLite 3.x database") !== -1) {
      const sqlite = await parseSqlite(file);
      const label = buildSqliteLabel(sqlite);
      if (label) return label;
      return magic;
    }
    return magic;
  }

  if (hasZipEocdSignature(dv)) return "ZIP archive";

  const mzKind = await probeMzFormat(file, dv);
  if (mzKind) {
    if (mzKind.kind === "pe") {
      const peHeaderOffset = mzKind.eLfanew >>> 0;
      const coff = await parseCoffHeader(file, peHeaderOffset);
      if (!coff) return "PE (unreadable)";
      const optionalHeaderOffset = peHeaderOffset + 24;
      const magicView = new DataView(await file.slice(optionalHeaderOffset, optionalHeaderOffset + 2).arrayBuffer());
      const magic = magicView.byteLength >= 2 ? magicView.getUint16(0, true) : 0;
      const sig = magic === 0x20b ? "PE32+" : "PE32";
      const isDll = (coff.Characteristics & 0x2000) !== 0 ? "DLL" : "executable";
      return `${sig} ${isDll} for ${mapMachine(coff.Machine)}`;
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
