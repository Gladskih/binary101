"use strict";

import { isPeWindowsParseResult, parsePe } from "./pe/index.js";
import { parseJpeg } from "./jpeg/index.js";
import { parseElf } from "./elf/index.js";
import { parseMachO } from "./macho/index.js";
import { parseFb2 } from "./fb2/index.js";
import { isGifSignature, parseGif } from "./gif/index.js";
import { parseZip } from "./zip/index.js";
import { parsePng } from "./png/index.js";
import { parseBmp } from "./bmp/index.js";
import { isTgaFileName, parseTga } from "./tga/index.js";
import { parsePdf } from "./pdf/index.js";
import { parseWebp } from "./webp/index.js";
import { parseWebm } from "./webm/index.js";
import { parseMp3, probeMp3 } from "./mp3/index.js";
import { parseFlac } from "./flac/index.js";
import { hasSevenZipSignature, parseSevenZip } from "./sevenz/index.js";
import { hasTarSignature, parseTar } from "./tar/index.js";
import { hasRarSignature, parseRar } from "./rar/index.js";
import { hasIso9660Signature, parseIso9660 } from "./iso9660/index.js";
import { parseMz } from "./mz/index.js";
import { hasShellLinkSignature, parseLnk } from "./lnk/index.js";
import { parseMp4 } from "./mp4/index.js";
import { parseWav } from "./wav/index.js";
import { parseAvi } from "./avi/index.js";
import { parseAni } from "./ani/index.js";
import { readFourCc } from "./riff/index.js";
import { parseAsf } from "./asf/index.js";
import { ASF_HEADER_GUID } from "./asf/constants.js";
import { guidToString as readAsfGuid } from "./asf/shared.js";
import type { ParseForUiResult } from "./analyzer-types.js";
import { detectPdfVersion, hasZipEocdSignature, toAsciiFromWholeView } from "./detection-labels.js";
import { probeElf } from "./elf/probe.js";
import { isShortMp3WithoutSecond, isValidatedMp3 } from "./mp3-labels.js";
import { probeMachO } from "./macho/probe.js";
import { probeMzFormat } from "./mz-probe.js";
import { hasSqliteSignature, parseSqlite } from "./sqlite/index.js";
import { parseMpegPs } from "./mpegps/index.js";
import { parsePcap } from "./pcap/index.js";
import { parsePcapNg } from "./pcapng/index.js";
import { parseGzip } from "./gzip/index.js";
import type { GzipParseResult } from "./gzip/types.js";
import { enrichPeImportMetadata } from "./pe/imports/api-metadata.js";

type Fb2Parser = typeof parseFb2;
type GzipParser = (file: File) => Promise<GzipParseResult | null>;
const parseGzipFile: GzipParser = parseGzip;

const tryContainerHeaderFormats = async (
  file: File,
  dv: DataView
): Promise<ParseForUiResult | null> => {
  if (hasShellLinkSignature(dv)) {
    const lnk = await parseLnk(file);
    if (lnk) return { analyzer: "lnk", parsed: lnk };
  }
  if (probeElf(dv)) {
    const elf = await parseElf(file);
    if (elf) return { analyzer: "elf", parsed: elf };
  }
  if (probeMachO(dv, file.size)) {
    const macho = await parseMachO(file);
    if (macho) return { analyzer: "macho", parsed: macho };
  }
  return null;
};

const tryMzFormats = async (file: File, dv: DataView): Promise<ParseForUiResult | null> => {
  const mzKind = await probeMzFormat(file, dv);
  if (!mzKind) return null;
  if (mzKind.kind === "pe") {
    const pe = await parsePe(file);
    if (pe) {
      return {
        analyzer: "pe",
        parsed: isPeWindowsParseResult(pe) ? await enrichPeImportMetadata(pe) : pe
      };
    }
  }
  const mz = await parseMz(file);
  if (!mz) return null;
  if (mzKind.kind && mzKind.kind !== "mz") mz.nextHeader = mzKind.kind;
  return { analyzer: "mz", parsed: mz };
};

const tryArchiveFormats = async (
  file: File,
  dv: DataView,
  parseFb2File: Fb2Parser
): Promise<ParseForUiResult | null> => {
  if (toAsciiFromWholeView(dv, 8192).toLowerCase().indexOf("<fictionbook") !== -1) {
    const fb2 = await parseFb2File(file);
    if (fb2) return { analyzer: "fb2", parsed: fb2 };
  }
  if (isGifSignature(dv)) {
    const gif = await parseGif(file);
    if (gif) return { analyzer: "gif", parsed: gif };
  }
  if (hasSevenZipSignature(dv)) {
    const sevenZip = await parseSevenZip(file);
    if (sevenZip?.is7z) return { analyzer: "sevenZip", parsed: sevenZip };
  }
  if (hasRarSignature(dv)) {
    const rar = await parseRar(file);
    if (rar?.isRar) return { analyzer: "rar", parsed: rar };
  }
  if (hasIso9660Signature(dv)) {
    const iso = await parseIso9660(file);
    if (iso) return { analyzer: "iso9660", parsed: iso };
  }
  if (hasTarSignature(dv)) {
    const tar = await parseTar(file);
    if (tar?.isTar) return { analyzer: "tar", parsed: tar };
  }
  if (dv.byteLength >= 2 && dv.getUint16(0, true) === 0x8b1f) {
    const gzip = await parseGzipFile(file);
    if (gzip) return { analyzer: "gzip", parsed: gzip };
  }
  if (dv.byteLength >= 4 && dv.getUint32(0, true) === 0x04034b50) {
    const zip = await parseZip(file);
    if (zip) return { analyzer: "zip", parsed: zip };
  }
  return null;
};

const hasTgaFooterSignature = async (file: File): Promise<boolean> => {
  if (file.size < 26) return false;
  const tail = new DataView(await file.slice(file.size - 26, file.size).arrayBuffer());
  if (tail.byteLength < 26) return false;
  let signature = "";
  for (let index = 0; index < 16 && 8 + index < tail.byteLength; index += 1) {
    const byteValue = tail.getUint8(8 + index);
    if (byteValue === 0) break;
    signature += String.fromCharCode(byteValue);
  }
  return (
    signature === "TRUEVISION-XFILE" &&
    tail.getUint8(24) === 0x2e &&
    tail.getUint8(25) === 0x00
  );
};

const tryImageFormats = async (file: File, dv: DataView): Promise<ParseForUiResult | null> => {
  if (dv.byteLength >= 5 && detectPdfVersion(dv)) {
    const pdf = await parsePdf(file);
    if (pdf) return { analyzer: "pdf", parsed: pdf };
  }
  if (dv.byteLength >= 8 && dv.getUint32(0, false) === 0x89504e47 && dv.getUint32(4, false) === 0x0d0a1a0a) {
    const png = await parsePng(file);
    if (png) return { analyzer: "png", parsed: png };
  }
  if (dv.byteLength >= 2 && dv.getUint16(0, false) === 0xffd8) {
    const jpeg = await parseJpeg(file);
    if (jpeg) return { analyzer: "jpeg", parsed: jpeg };
  }
  if (dv.byteLength >= 2 && dv.getUint16(0, false) === 0x424d) {
    const bmp = await parseBmp(file);
    if (bmp) return { analyzer: "bmp", parsed: bmp };
  }
  if (isTgaFileName(file.name) || await hasTgaFooterSignature(file)) {
    const tga = await parseTga(file);
    if (tga) return { analyzer: "tga", parsed: tga };
  }
  return null;
};

const tryRiffFormat = async (file: File, dv: DataView): Promise<ParseForUiResult | null> => {
  if (dv.byteLength < 12) return null;
  const riff = dv.getUint32(0, false);
  if (riff !== 0x52494646 && riff !== 0x52494658) return null;
  const formType = readFourCc(dv, 8);
  if (formType === "WEBP") {
    const parsedWebp = await parseWebp(file);
    if (parsedWebp) return { analyzer: "webp", parsed: parsedWebp };
  } else if (formType === "WAVE") {
    const wav = await parseWav(file);
    if (wav) return { analyzer: "wav", parsed: wav };
  } else if (formType === "AVI " || formType === "AVIX") {
    const avi = await parseAvi(file);
    if (avi) return { analyzer: "avi", parsed: avi };
  } else if (formType === "ACON") {
    const ani = await parseAni(file);
    if (ani) return { analyzer: "ani", parsed: ani };
  }
  return null;
};

const tryPacketCaptureFormat = async (
  file: File,
  dv: DataView
): Promise<ParseForUiResult | null> => {
  if (dv.byteLength < 4) return null;
  const sig = dv.getUint32(0, false);
  if (sig === 0x0a0d0d0a) {
    const pcapng = await parsePcapNg(file);
    if (pcapng) return { analyzer: "pcapng", parsed: pcapng };
  } else if (
    sig === 0xa1b2c3d4 ||
    sig === 0xa1b23c4d ||
    sig === 0xd4c3b2a1 ||
    sig === 0x4d3cb2a1
  ) {
    const pcap = await parsePcap(file);
    if (pcap) return { analyzer: "pcap", parsed: pcap };
  }
  return null;
};

const tryIsoMediaFormat = async (file: File, dv: DataView): Promise<ParseForUiResult | null> => {
  if (dv.byteLength < 12 || dv.getUint32(4, false) !== 0x66747970) return null;
  const brand = dv.getUint32(8, false);
  if (brand === 0x68656963 || brand === 0x68656978 || brand === 0x68657663) return null;
  const mp4 = await parseMp4(file);
  return mp4 ? { analyzer: "mp4", parsed: mp4 } : null;
};

const tryStreamingMediaFormats = async (
  file: File,
  dv: DataView
): Promise<ParseForUiResult | null> => {
  const riff = await tryRiffFormat(file, dv);
  if (riff) return riff;
  if (dv.byteLength >= 16 && readAsfGuid(dv, 0) === ASF_HEADER_GUID) {
    const asf = await parseAsf(file);
    if (asf) return { analyzer: "asf", parsed: asf };
  }
  const packetCapture = await tryPacketCaptureFormat(file, dv);
  if (packetCapture) return packetCapture;
  const isoMedia = await tryIsoMediaFormat(file, dv);
  if (isoMedia) return isoMedia;
  if (dv.byteLength >= 4 && dv.getUint32(0, false) === 0x000001ba) {
    const mpegps = await parseMpegPs(file);
    if (mpegps) return { analyzer: "mpegps", parsed: mpegps };
  }
  if (dv.byteLength >= 4 && dv.getUint32(0, false) === 0x1a45dfa3) {
    const webm = await parseWebm(file);
    if (webm) return { analyzer: webm.isWebm ? "webm" : "mkv", parsed: webm };
  }
  return null;
};

const tryAudioAndDatabaseFormats = async (
  file: File,
  dv: DataView
): Promise<ParseForUiResult | null> => {
  if (dv.byteLength >= 4 && dv.getUint32(0, false) === 0x664c6143) {
    const flac = await parseFlac(file);
    if (flac) return { analyzer: "flac", parsed: flac };
  }
  if (hasSqliteSignature(dv)) {
    const sqlite = await parseSqlite(file);
    if (sqlite) return { analyzer: "sqlite", parsed: sqlite };
  }
  if (probeMp3(dv)) {
    const mp3 = await parseMp3(file);
    if (isValidatedMp3(mp3) || isShortMp3WithoutSecond(mp3)) {
      return { analyzer: "mp3", parsed: mp3 };
    }
  }
  if (hasZipEocdSignature(dv)) {
    const zip = await parseZip(file);
    if (zip) return { analyzer: "zip", parsed: zip };
  }
  return null;
};

const createParseForUi = (parseFb2File: typeof parseFb2 = parseFb2) => {
  return async (file: File): Promise<ParseForUiResult> => {
    const dv = new DataView(
      await file.slice(0, Math.min(file.size, 65536)).arrayBuffer()
    );
    const earlyFormat = await tryContainerHeaderFormats(file, dv);
    if (earlyFormat) return earlyFormat;
    const mzFormat = await tryMzFormats(file, dv);
    if (mzFormat) return mzFormat;
    const archiveFormat = await tryArchiveFormats(file, dv, parseFb2File);
    if (archiveFormat) return archiveFormat;
    const imageFormat = await tryImageFormats(file, dv);
    if (imageFormat) return imageFormat;
    const streamingMediaFormat = await tryStreamingMediaFormats(file, dv);
    if (streamingMediaFormat) return streamingMediaFormat;
    const audioOrDatabaseFormat = await tryAudioAndDatabaseFormats(file, dv);
    if (audioOrDatabaseFormat) return audioOrDatabaseFormat;
    return { analyzer: null, parsed: null };
  };
};

const parseForUi = createParseForUi();

export { createParseForUi, parseForUi };
