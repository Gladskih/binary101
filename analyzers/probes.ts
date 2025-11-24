/* eslint-disable max-lines */
// @ts-nocheck
"use strict";

// Quick magic/text-based probes for common formats (label only; no parsing yet)

const MAX_TEXT_INSPECT_BYTES = 256;

function toAsciiPrefix(dv, maxBytes) {
  const limit = Math.min(dv.byteLength, maxBytes);
  let result = "";
  for (let i = 0; i < limit; i += 1) {
    const code = dv.getUint8(i);
    if (code === 0) break;
    if (code < 0x09) return "";
    result += String.fromCharCode(code);
  }
  return result;
}

function isMostlyText(dv) {
  if (dv.byteLength === 0) return false;
  const limit = Math.min(dv.byteLength, MAX_TEXT_INSPECT_BYTES);
  let printable = 0;
  let control = 0;
  for (let i = 0; i < limit; i += 1) {
    const c = dv.getUint8(i);
    if (c === 0) {
      control += 1;
      continue;
    }
    if (c === 0x09 || c === 0x0a || c === 0x0d) {
      printable += 1;
      continue;
    }
    if (c >= 0x20 && c <= 0x7e) {
      printable += 1;
    } else {
      control += 1;
    }
  }
  return printable > 0 && control * 4 <= printable;
}

// --- Binary/container probes (non-PE) ---

function detectPdf(dv) {
  if (dv.byteLength < 5) return null;
  const m =
    String.fromCharCode(dv.getUint8(0)) +
    String.fromCharCode(dv.getUint8(1)) +
    String.fromCharCode(dv.getUint8(2)) +
    String.fromCharCode(dv.getUint8(3)) +
    String.fromCharCode(dv.getUint8(4));
  return m === "%PDF-" ? "PDF document" : null;
}

function detectZip(dv) {
  if (dv.byteLength < 4) return null;
  const sig = dv.getUint32(0, true);
  return sig === 0x04034b50 ? "ZIP archive (PK-based, e.g. Office, JAR, APK)" : null;
}

function detectGzip(dv) {
  if (dv.byteLength < 2) return null;
  const sig = dv.getUint16(0, true);
  return sig === 0x8b1f ? "gzip compressed data" : null;
}

function detectBzip2(dv) {
  if (dv.byteLength < 3) return null;
  const b0 = dv.getUint8(0);
  const b1 = dv.getUint8(1);
  const b2 = dv.getUint8(2);
  return b0 === 0x42 && b1 === 0x5a && b2 === 0x68 ? "bzip2 compressed data" : null;
}

function detectSevenZip(dv) {
  if (dv.byteLength < 6) return null;
  const b0 = dv.getUint8(0);
  const b1 = dv.getUint8(1);
  const b2 = dv.getUint8(2);
  const b3 = dv.getUint8(3);
  const b4 = dv.getUint8(4);
  const b5 = dv.getUint8(5);
  if (
    b0 === 0x37 &&
    b1 === 0x7a &&
    b2 === 0xbc &&
    b3 === 0xaf &&
    b4 === 0x27 &&
    b5 === 0x1c
  ) {
    return "7z archive";
  }
  return null;
}

function detectXz(dv) {
  if (dv.byteLength < 6) return null;
  const b0 = dv.getUint8(0);
  const b1 = dv.getUint8(1);
  const b2 = dv.getUint8(2);
  const b3 = dv.getUint8(3);
  const b4 = dv.getUint8(4);
  const b5 = dv.getUint8(5);
  if (
    b0 === 0xfd &&
    b1 === 0x37 &&
    b2 === 0x7a &&
    b3 === 0x58 &&
    b4 === 0x5a &&
    b5 === 0x00
  ) {
    return "XZ compressed data";
  }
  return null;
}

function detectLz4(dv) {
  if (dv.byteLength < 4) return null;
  const b0 = dv.getUint8(0);
  const b1 = dv.getUint8(1);
  const b2 = dv.getUint8(2);
  const b3 = dv.getUint8(3);
  if (b0 === 0x04 && b1 === 0x22 && b2 === 0x4d && b3 === 0x18) {
    return "LZ4 frame";
  }
  return null;
}

function detectZstd(dv) {
  if (dv.byteLength < 4) return null;
  const b0 = dv.getUint8(0);
  const b1 = dv.getUint8(1);
  const b2 = dv.getUint8(2);
  const b3 = dv.getUint8(3);
  if (b0 === 0x28 && b1 === 0xb5 && b2 === 0x2f && b3 === 0xfd) {
    return "Zstandard compressed data (zstd)";
  }
  return null;
}

function detectRar(dv) {
  if (dv.byteLength < 7) return null;
  const m =
    String.fromCharCode(dv.getUint8(0)) +
    String.fromCharCode(dv.getUint8(1)) +
    String.fromCharCode(dv.getUint8(2)) +
    String.fromCharCode(dv.getUint8(3));
  if (m !== "Rar!") return null;
  const b4 = dv.getUint8(4);
  const b5 = dv.getUint8(5);
  return b4 === 0x1a && b5 === 0x07 ? "RAR archive" : null;
}

function detectCab(dv) {
  if (dv.byteLength < 4) return null;
  const sig = dv.getUint32(0, false);
  return sig === 0x4d534346 ? "Microsoft Cabinet archive (CAB)" : null;
}

function detectPng(dv) {
  if (dv.byteLength < 8) return null;
  const sig0 = dv.getUint32(0, false);
  const sig1 = dv.getUint32(4, false);
  return sig0 === 0x89504e47 && sig1 === 0x0d0a1a0a ? "PNG image" : null;
}

function detectJpeg(dv) {
  if (dv.byteLength < 4) return null;
  const marker = dv.getUint16(0, false);
  if (marker !== 0xffd8) return null;
  const jfif = dv.byteLength >= 11 && dv.getUint32(2, false) === 0x4a464946; // "JFIF"
  const exif = dv.byteLength >= 11 && dv.getUint32(2, false) === 0x45786966; // "Exif"
  if (jfif) return "JPEG image (JFIF)";
  if (exif) return "JPEG image (EXIF)";
  return "JPEG image";
}

function detectGif(dv) {
  if (dv.byteLength < 6) return null;
  const sig =
    String.fromCharCode(dv.getUint8(0)) +
    String.fromCharCode(dv.getUint8(1)) +
    String.fromCharCode(dv.getUint8(2)) +
    String.fromCharCode(dv.getUint8(3)) +
    String.fromCharCode(dv.getUint8(4)) +
    String.fromCharCode(dv.getUint8(5));
  if (sig === "GIF87a" || sig === "GIF89a") return "GIF image";
  return null;
}

function detectBmp(dv) {
  if (dv.byteLength < 2) return null;
  const sig = dv.getUint16(0, false);
  return sig === 0x424d ? "BMP bitmap image" : null;
}

function detectTiff(dv) {
  if (dv.byteLength < 4) return null;
  const sig = dv.getUint32(0, false);
  if (sig === 0x49492a00 || sig === 0x4d4d002a) return "TIFF image";
  return null;
}

function detectWebp(dv) {
  if (dv.byteLength < 12) return null;
  const riff = dv.getUint32(0, false);
  const webp = dv.getUint32(8, false);
  return riff === 0x52494646 && webp === 0x57454250 ? "WebP image" : null;
}

function detectIco(dv) {
  if (dv.byteLength < 4) return null;
  const reserved = dv.getUint16(0, true);
  const type = dv.getUint16(2, true);
  if (reserved === 0 && (type === 1 || type === 2)) {
    return "ICO/CUR icon image";
  }
  return null;
}

function detectAni(dv) {
  if (dv.byteLength < 12) return null;
  const riff = dv.getUint32(0, false);
  const acon = dv.getUint32(8, false);
  if (riff === 0x52494646 && acon === 0x41434f4e) return "Windows animated cursor (ANI)";
  return null;
}

function detectFlac(dv) {
  if (dv.byteLength < 4) return null;
  const sig = dv.getUint32(0, false);
  return sig === 0x664c6143 ? "FLAC audio" : null;
}

function detectCompoundFile(dv) {
  if (dv.byteLength < 8) return null;
  const b0 = dv.getUint8(0);
  const b1 = dv.getUint8(1);
  const b2 = dv.getUint8(2);
  const b3 = dv.getUint8(3);
  const b4 = dv.getUint8(4);
  const b5 = dv.getUint8(5);
  const b6 = dv.getUint8(6);
  const b7 = dv.getUint8(7);
  if (
    b0 === 0xd0 &&
    b1 === 0xcf &&
    b2 === 0x11 &&
    b3 === 0xe0 &&
    b4 === 0xa1 &&
    b5 === 0xb1 &&
    b6 === 0x1a &&
    b7 === 0xe1
  ) {
    return "Microsoft Compound File (e.g. Office 97-2003, MSI)";
  }
  return null;
}

function detectPdb(dv) {
  if (dv.byteLength < 32) return null;
  const limit = Math.min(dv.byteLength, 64);
  let header = "";
  for (let i = 0; i < limit; i += 1) {
    const c = dv.getUint8(i);
    if (c === 0) break;
    header += String.fromCharCode(c);
  }
  if (!header) return null;
  const lower = header.toLowerCase();
  if (!lower.startsWith("microsoft c/c++")) return null;
  if (
    lower.indexOf("program database") !== -1 ||
    lower.indexOf("msf 7.00") !== -1
  ) {
    return "Microsoft PDB debug symbols";
  }
  return null;
}

function detectOgg(dv) {
  if (dv.byteLength < 4) return null;
  const sig = dv.getUint32(0, false);
  return sig === 0x4f676753 ? "Ogg container (Vorbis/Opus/FLAC)" : null;
}

function detectWav(dv) {
  if (dv.byteLength < 12) return null;
  const riff = dv.getUint32(0, false);
  const wave = dv.getUint32(8, false);
  if (riff === 0x52494646 && wave === 0x57415645) return "WAVE audio (RIFF)";
  return null;
}

function detectAiff(dv) {
  if (dv.byteLength < 12) return null;
  const form = dv.getUint32(0, false);
  const aiff = dv.getUint32(8, false);
  if (form === 0x464f524d && (aiff === 0x41494646 || aiff === 0x41494643)) {
    return "AIFF/AIFFC audio";
  }
  return null;
}

function detectMidi(dv) {
  if (dv.byteLength < 4) return null;
  const sig = dv.getUint32(0, false);
  return sig === 0x4d546864 ? "MIDI audio" : null;
}

function detectAmr(dv) {
  if (dv.byteLength < 6) return null;
  let header = "";
  const limit = Math.min(dv.byteLength, 9);
  for (let i = 0; i < limit; i += 1) {
    const c = dv.getUint8(i);
    if (c === 0) break;
    header += String.fromCharCode(c);
  }
  if (header.startsWith("#!AMR")) return "AMR audio";
  return null;
}

function detectAc3(dv) {
  if (dv.byteLength < 2) return null;
  const b0 = dv.getUint8(0);
  const b1 = dv.getUint8(1);
  if (b0 === 0x0b && b1 === 0x77) return "Dolby AC-3 audio";
  return null;
}

function detectDts(dv) {
  if (dv.byteLength < 4) return null;
  const b0 = dv.getUint8(0);
  const b1 = dv.getUint8(1);
  const b2 = dv.getUint8(2);
  const b3 = dv.getUint8(3);
  if (b0 === 0x7f && b1 === 0xfe && b2 === 0x80 && b3 === 0x01) {
    return "DTS audio";
  }
  return null;
}

function detectMp3OrAac(dv) {
  if (dv.byteLength < 2) return null;
  const id3 =
    dv.byteLength >= 3 &&
    String.fromCharCode(dv.getUint8(0)) +
      String.fromCharCode(dv.getUint8(1)) +
      String.fromCharCode(dv.getUint8(2)) === "ID3";
  if (id3) return "MPEG audio with ID3 tag (MP3/AAC)";
  const b0 = dv.getUint8(0);
  const b1 = dv.getUint8(1);
  if (b0 === 0xff && (b1 & 0xe0) === 0xe0) {
    // Avoid misclassifying UTF-16 BOM (0xff 0xfe) and similar text headers.
    if (b1 === 0xfe) return null;
    return "MPEG audio stream (MP3/AAC)";
  }
  return null;
}

function detectFlv(dv) {
  if (dv.byteLength < 3) return null;
  const sig =
    String.fromCharCode(dv.getUint8(0)) +
    String.fromCharCode(dv.getUint8(1)) +
    String.fromCharCode(dv.getUint8(2));
  return sig === "FLV" ? "FLV video" : null;
}

function detectAvi(dv) {
  if (dv.byteLength < 12) return null;
  const riff = dv.getUint32(0, false);
  const avi = dv.getUint32(8, false);
  if (riff === 0x52494646 && avi === 0x41564920) return "AVI/DivX video (RIFF)";
  return null;
}

function detectAsf(dv) {
  if (dv.byteLength < 16) return null;
  const b0 = dv.getUint8(0);
  const b1 = dv.getUint8(1);
  const b2 = dv.getUint8(2);
  const b3 = dv.getUint8(3);
  const b4 = dv.getUint8(4);
  const b5 = dv.getUint8(5);
  const b6 = dv.getUint8(6);
  const b7 = dv.getUint8(7);
  const b8 = dv.getUint8(8);
  const b9 = dv.getUint8(9);
  const b10 = dv.getUint8(10);
  const b11 = dv.getUint8(11);
  const b12 = dv.getUint8(12);
  const b13 = dv.getUint8(13);
  const b14 = dv.getUint8(14);
  const b15 = dv.getUint8(15);
  if (
    b0 === 0x30 && b1 === 0x26 && b2 === 0xb2 && b3 === 0x75 &&
    b4 === 0x8e && b5 === 0x66 && b6 === 0xcf && b7 === 0x11 &&
    b8 === 0xa6 && b9 === 0xd9 && b10 === 0x00 && b11 === 0xaa &&
    b12 === 0x00 && b13 === 0x62 && b14 === 0xce && b15 === 0x6c
  ) {
    return "ASF container (WMA/WMV)";
  }
  return null;
}

function detectIsoBmff(dv) {
  if (dv.byteLength < 12) return null;
  const ftyp = dv.getUint32(4, false);
  if (ftyp !== 0x66747970) return null;
  const brand = dv.getUint32(8, false);
  if (
    brand === 0x68656963 || // heic
    brand === 0x68656978 || // heix
    brand === 0x68657663 // hevc
  ) {
    return "HEIF/HEIC image (ISO-BMFF)";
  }
  if (
    brand === 0x33677034 || // 3gp4
    brand === 0x33677035 || // 3gp5
    brand === 0x33677036 // 3gp6
  ) {
    return "3GPP/3GP container (ISO-BMFF)";
  }
  if (
    brand === 0x69736f6d || // isom
    brand === 0x69736f32 || // iso2
    brand === 0x6d703431 || // mp41
    brand === 0x6d703432 || // mp42
    brand === 0x4d345620 || // M4V
    brand === 0x4d344120 || // M4A
    brand === 0x71742020 // qt
  ) {
    return "MP4/QuickTime container (ISO-BMFF)";
  }
  return "ISO-BMFF container (MP4/3GP/QuickTime/HEIF)";
}

function detectMpegPs(dv) {
  if (dv.byteLength < 4) return null;
  const sig = dv.getUint32(0, false);
  return sig === 0x000001ba ? "MPEG Program Stream (MPG)" : null;
}

function detectMpegTs(dv) {
  const packetSize = 188;
  if (dv.byteLength < packetSize * 3) return null;
  if (
    dv.getUint8(0) !== 0x47 ||
    dv.getUint8(packetSize) !== 0x47 ||
    dv.getUint8(packetSize * 2) !== 0x47
  ) {
    return null;
  }
  return "MPEG Transport Stream (TS)";
}

function detectRealMedia(dv) {
  if (dv.byteLength < 4) return null;
  const sig = dv.getUint32(0, false);
  return sig === 0x2e524d46 ? "RealMedia container (RM/RMVB)" : null;
}

function detectMatroska(dv) {
  if (dv.byteLength < 4) return null;
  const sig = dv.getUint32(0, false);
  if (sig !== 0x1a45dfa3) return null;
  return "Matroska/WebM container";
}

function detectTar(dv) {
  if (dv.byteLength < 262) return null;
  const offset = 257;
  const u =
    String.fromCharCode(dv.getUint8(offset + 0)) +
    String.fromCharCode(dv.getUint8(offset + 1)) +
    String.fromCharCode(dv.getUint8(offset + 2)) +
    String.fromCharCode(dv.getUint8(offset + 3)) +
    String.fromCharCode(dv.getUint8(offset + 4));
  return u === "ustar" ? "TAR archive" : null;
}

function detectSqlite(dv) {
  if (dv.byteLength < 16) return null;
  const prefix = toAsciiPrefix(dv, 16);
  return prefix.startsWith("SQLite format 3") ? "SQLite 3.x database" : null;
}

function detectJavaClass(dv) {
  if (dv.byteLength < 4) return null;
  const sig = dv.getUint32(0, false);
  return sig === 0xcafebabe ? "Java class file" : null;
}

function detectIso9660(dv) {
  const markers = [0x8001, 0x8801, 0x9001];
  for (let i = 0; i < markers.length; i += 1) {
    const offset = markers[i];
    if (dv.byteLength < offset + 5) continue;
    const s =
      String.fromCharCode(dv.getUint8(offset + 0)) +
      String.fromCharCode(dv.getUint8(offset + 1)) +
      String.fromCharCode(dv.getUint8(offset + 2)) +
      String.fromCharCode(dv.getUint8(offset + 3)) +
      String.fromCharCode(dv.getUint8(offset + 4));
    if (s === "CD001") {
      return "ISO-9660 CD/DVD image (ISO)";
    }
  }
  return null;
}

function detectDjvu(dv) {
  if (dv.byteLength < 16) return null;
  const header =
    String.fromCharCode(dv.getUint8(0)) +
    String.fromCharCode(dv.getUint8(1)) +
    String.fromCharCode(dv.getUint8(2)) +
    String.fromCharCode(dv.getUint8(3)) +
    String.fromCharCode(dv.getUint8(4)) +
    String.fromCharCode(dv.getUint8(5)) +
    String.fromCharCode(dv.getUint8(6)) +
    String.fromCharCode(dv.getUint8(7));
  if (header !== "AT&TFORM") return null;
  const id =
    String.fromCharCode(dv.getUint8(12)) +
    String.fromCharCode(dv.getUint8(13)) +
    String.fromCharCode(dv.getUint8(14)) +
    String.fromCharCode(dv.getUint8(15));
  if (id === "DJVU" || id === "DJVM" || id === "DJVI") {
    return "DjVu document";
  }
  return null;
}

function detectPcap(dv) {
  if (dv.byteLength < 4) return null;
  const sigBE = dv.getUint32(0, false);
  const sigLE = dv.getUint32(0, true);
  if (
    sigBE === 0xa1b2c3d4 ||
    sigBE === 0xa1b23c4d ||
    sigLE === 0xa1b2c3d4 ||
    sigLE === 0xa1b23c4d
  ) {
    return "PCAP capture file";
  }
  return null;
}

function detectPcapNg(dv) {
  if (dv.byteLength < 4) return null;
  const sig = dv.getUint32(0, false);
  return sig === 0x0a0d0d0a ? "PCAP-NG capture file" : null;
}

function detectLnk(dv) {
  if (dv.byteLength < 0x14) return null;
  const size = dv.getUint32(0, true);
  if (size !== 0x0000004c) return null;
  const clsid =
    dv.getUint32(4, true) === 0x00021401 &&
    dv.getUint16(8, true) === 0x0000 &&
    dv.getUint16(10, true) === 0x0000 &&
    dv.getUint8(12) === 0xc0 &&
    dv.getUint8(13) === 0x00 &&
    dv.getUint8(14) === 0x00 &&
    dv.getUint8(15) === 0x00 &&
    dv.getUint8(16) === 0x00 &&
    dv.getUint8(17) === 0x00 &&
    dv.getUint8(18) === 0x00 &&
    dv.getUint8(19) === 0x46;
  if (!clsid) return null;
  return "Windows shortcut (.lnk)";
}

function detectWasM(dv) {
  if (dv.byteLength < 4) return null;
  const sig = dv.getUint32(0, false);
  return sig === 0x0061736d ? "WebAssembly binary (WASM)" : null;
}

function detectDex(dv) {
  if (dv.byteLength < 8) return null;
  const prefix =
    String.fromCharCode(dv.getUint8(0)) +
    String.fromCharCode(dv.getUint8(1)) +
    String.fromCharCode(dv.getUint8(2)) +
    String.fromCharCode(dv.getUint8(3));
  if (prefix !== "dex\n") return null;
  return "Android DEX bytecode";
}

function detectWinHelp(dv) {
  if (dv.byteLength < 4) return null;
  const b0 = dv.getUint8(0);
  const b1 = dv.getUint8(1);
  const b2 = dv.getUint8(2);
  const b3 = dv.getUint8(3);
  if (b0 === 0x3f && b1 === 0x5f && b2 === 0x03 && b3 === 0x00) {
    return "Windows Help file (HLP)";
  }
  return null;
}

// --- Text-like probes ---

function detectScriptShebang(dv) {
  if (dv.byteLength < 2) return null;
  const b0 = dv.getUint8(0);
  const b1 = dv.getUint8(1);
  if (b0 === 0x23 && b1 === 0x21) return "Text script (shebang)";
  return null;
}

function detectHtml(dv) {
  const text = toAsciiPrefix(dv, MAX_TEXT_INSPECT_BYTES).trimStart().toLowerCase();
  if (text.startsWith("<!doctype html") || text.startsWith("<html")) {
    return "HTML document";
  }
  return null;
}

function detectXmlOrSvg(dv) {
  const text = toAsciiPrefix(dv, MAX_TEXT_INSPECT_BYTES).trimStart();
  const lower = text.toLowerCase();
  if (!lower.startsWith("<?xml")) return null;
  if (lower.includes("<svg")) return "SVG image (XML)";
  return "XML document";
}

function detectJson(dv) {
  const text = toAsciiPrefix(dv, MAX_TEXT_INSPECT_BYTES).trimStart();
  if (!text) return null;
  const first = text[0];
  if (first !== "{" && first !== "[") return null;
  const hasQuote = text.indexOf("\"") !== -1;
  const hasColon = text.indexOf(":") !== -1;
  if (!hasQuote && !hasColon) return null;
  return "JSON data";
}

function detectRtf(dv) {
  const text = toAsciiPrefix(dv, MAX_TEXT_INSPECT_BYTES).trimStart();
  if (!text) return null;
  if (text.startsWith("{\\rtf")) return "RTF document";
  return null;
}

function detectFb2Xml(dv) {
  const text = toAsciiPrefix(dv, MAX_TEXT_INSPECT_BYTES).trimStart().toLowerCase();
  if (!text) return null;
  if (text.indexOf("<fictionbook") !== -1) return "FictionBook e-book (FB2)";
  return null;
}

function detectPlainText(dv) {
  if (!isMostlyText(dv)) return null;
  return "Text file";
}

const MAGIC_PROBES = [
  detectPdf,
  detectZip,
  detectGzip,
  detectBzip2,
  detectSevenZip,
  detectXz,
  detectLz4,
  detectZstd,
  detectRar,
  detectCab,
  detectPng,
  detectJpeg,
  detectGif,
  detectBmp,
  detectTiff,
  detectWebp,
  detectIco,
  detectAni,
  detectFlac,
  detectCompoundFile,
  detectPdb,
  detectOgg,
  detectWav,
  detectAiff,
  detectMidi,
  detectAmr,
  detectAc3,
  detectDts,
  detectMp3OrAac,
  detectFlv,
  detectAvi,
  detectAsf,
  detectIsoBmff,
  detectMpegPs,
  detectMpegTs,
  detectRealMedia,
  detectMatroska,
  detectTar,
  detectSqlite,
  detectJavaClass,
  detectIso9660,
  detectDjvu,
  detectPcapNg,
  detectPcap,
  detectLnk,
  detectWasM,
  detectDex,
  detectWinHelp
];

const TEXT_PROBES = [
  detectScriptShebang,
  detectHtml,
  detectFb2Xml,
  detectXmlOrSvg,
  detectRtf,
  detectJson,
  detectPlainText
];

export function probeByMagic(dv) {
  for (const probe of MAGIC_PROBES) {
    const label = probe(dv);
    if (label) return label;
  }
  return null;
}

export function probeTextLike(dv) {
  if (!isMostlyText(dv)) return null;
  for (const probe of TEXT_PROBES) {
    const label = probe(dv);
    if (label) return label;
  }
  return null;
}
