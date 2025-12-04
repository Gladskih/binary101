"use strict";

import { parsePe } from "./pe/index.js";
import { parseJpeg } from "./jpeg/index.js";
import { parseElf } from "./elf/index.js";
import { parseFb2 } from "./fb2/index.js";
import { isGifSignature, parseGif } from "./gif/index.js";
import { parseZip } from "./zip/index.js";
import { parsePng } from "./png/index.js";
import { parsePdf } from "./pdf/index.js";
import { parseWebp } from "./webp/index.js";
import { parseWebm } from "./webm/index.js";
import { parseMp3, probeMp3 } from "./mp3/index.js";
import { parseFlac } from "./flac/index.js";
import { hasSevenZipSignature, parseSevenZip } from "./sevenz/index.js";
import { hasTarSignature, parseTar } from "./tar/index.js";
import { hasRarSignature, parseRar } from "./rar/index.js";
import { parseMz } from "./mz/index.js";
import { hasShellLinkSignature, parseLnk } from "./lnk/index.js";
import { parseMp4 } from "./mp4/index.js";
import { parseWav } from "./wav/index.js";
import { parseAvi } from "./avi/index.js";
import { parseAni } from "./ani/index.js";
import { readFourCc } from "./riff/index.js";
import type { ParseForUiResult } from "./analyzer-types.js";
import { detectELF } from "./format-detectors.js";
import { detectPdfVersion, hasZipEocdSignature, toAsciiFromWholeView } from "./detection-labels.js";
import { isShortMp3WithoutSecond, isValidatedMp3 } from "./mp3-labels.js";
import { probeMzFormat } from "./mz-probe.js";

const parseForUi = async (file: File): Promise<ParseForUiResult> => {
  const dv = new DataView(
    await file.slice(0, Math.min(file.size, 65536)).arrayBuffer()
  );
  if (hasShellLinkSignature(dv)) {
    const lnk = await parseLnk(file);
    if (lnk) return { analyzer: "lnk", parsed: lnk };
  }
  if (detectELF(dv)) {
    const elf = await parseElf(file);
    if (elf) return { analyzer: "elf", parsed: elf };
  }
  const mzKind = await probeMzFormat(file, dv);
  if (mzKind) {
    if (mzKind.kind === "pe") {
      const pe = await parsePe(file);
      if (pe) return { analyzer: "pe", parsed: pe };
    }
    const mz = await parseMz(file);
    if (mz) {
      if (mzKind.kind && mzKind.kind !== "mz") mz.nextHeader = mzKind.kind;
      return { analyzer: "mz", parsed: mz };
    }
  }
  const ascii = toAsciiFromWholeView(dv, 8192).toLowerCase();
  if (ascii.indexOf("<fictionbook") !== -1) {
    const fb2 = await parseFb2(file);
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
  if (hasTarSignature(dv)) {
    const tar = await parseTar(file);
    if (tar?.isTar) return { analyzer: "tar", parsed: tar };
  }
  if (dv.byteLength >= 4 && dv.getUint32(0, true) === 0x04034b50) {
    const zip = await parseZip(file);
    if (zip) return { analyzer: "zip", parsed: zip };
  }
  if (dv.byteLength >= 5) {
    const pdfVersion = detectPdfVersion(dv);
    if (pdfVersion) {
      const pdf = await parsePdf(file);
      if (pdf) return { analyzer: "pdf", parsed: pdf };
    }
  }
  if (dv.byteLength >= 8) {
    const sig0 = dv.getUint32(0, false);
    const sig1 = dv.getUint32(4, false);
    if (sig0 === 0x89504e47 && sig1 === 0x0d0a1a0a) {
      const png = await parsePng(file);
      if (png) return { analyzer: "png", parsed: png };
    }
  }
  if (dv.byteLength >= 2 && dv.getUint16(0, false) === 0xffd8) {
    const jpeg = await parseJpeg(file);
    if (jpeg) return { analyzer: "jpeg", parsed: jpeg };
  }
  if (dv.byteLength >= 12) {
    const riff = dv.getUint32(0, false);
    if (riff === 0x52494646 || riff === 0x52494658) {
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
    }
  }
  if (dv.byteLength >= 12) {
    const ftyp = dv.getUint32(4, false);
    if (ftyp === 0x66747970) {
      const brand = dv.getUint32(8, false);
      if (brand !== 0x68656963 && brand !== 0x68656978 && brand !== 0x68657663) {
        const mp4 = await parseMp4(file);
        if (mp4) return { analyzer: "mp4", parsed: mp4 };
      }
    }
  }
  if (dv.byteLength >= 4 && dv.getUint32(0, false) === 0x1a45dfa3) {
    const webm = await parseWebm(file);
    if (webm) return { analyzer: "webm", parsed: webm };
  }
  if (dv.byteLength >= 4 && dv.getUint32(0, false) === 0x664c6143) {
    const flac = await parseFlac(file);
    if (flac) return { analyzer: "flac", parsed: flac };
  }
  if (probeMp3(dv)) {
    const mp3 = await parseMp3(file);
    if (isValidatedMp3(mp3) || isShortMp3WithoutSecond(mp3)) return { analyzer: "mp3", parsed: mp3 };
  }

  if (hasZipEocdSignature(dv)) {
    const zip = await parseZip(file);
    if (zip) return { analyzer: "zip", parsed: zip };
  }

  return { analyzer: null, parsed: null };
};

export { parseForUi };
