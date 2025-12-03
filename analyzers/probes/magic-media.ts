"use strict";
import type { ProbeResult } from "./probe-types.js";

const detectFlac = (dv: DataView): ProbeResult => {
  if (dv.byteLength < 4) return null;
  const sig = dv.getUint32(0, false);
  return sig === 0x664c6143 ? "FLAC audio" : null;
};

const detectOgg = (dv: DataView): ProbeResult => {
  if (dv.byteLength < 4) return null;
  const sig = dv.getUint32(0, false);
  return sig === 0x4f676753 ? "Ogg container (Vorbis/Opus/FLAC)" : null;
};

const detectWav = (dv: DataView): ProbeResult => {
  if (dv.byteLength < 12) return null;
  const riff = dv.getUint32(0, false);
  const wave = dv.getUint32(8, false);
  if (riff === 0x52494646 && wave === 0x57415645) return "WAVE audio (RIFF)";
  return null;
};

const detectAiff = (dv: DataView): ProbeResult => {
  if (dv.byteLength < 12) return null;
  const form = dv.getUint32(0, false);
  const aiff = dv.getUint32(8, false);
  if (form === 0x464f524d && (aiff === 0x41494646 || aiff === 0x41494643)) {
    return "AIFF/AIFFC audio";
  }
  return null;
};

const detectMidi = (dv: DataView): ProbeResult => {
  if (dv.byteLength < 4) return null;
  const sig = dv.getUint32(0, false);
  return sig === 0x4d546864 ? "MIDI audio" : null;
};

const detectAmr = (dv: DataView): ProbeResult => {
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
};

const detectAc3 = (dv: DataView): ProbeResult => {
  if (dv.byteLength < 2) return null;
  const b0 = dv.getUint8(0);
  const b1 = dv.getUint8(1);
  if (b0 === 0x0b && b1 === 0x77) return "Dolby AC-3 audio";
  return null;
};

const detectDts = (dv: DataView): ProbeResult => {
  if (dv.byteLength < 4) return null;
  const b0 = dv.getUint8(0);
  const b1 = dv.getUint8(1);
  const b2 = dv.getUint8(2);
  const b3 = dv.getUint8(3);
  if (b0 === 0x7f && b1 === 0xfe && b2 === 0x80 && b3 === 0x01) {
    return "DTS audio";
  }
  return null;
};

const detectMp3OrAac = (dv: DataView): ProbeResult => {
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
    if (b1 === 0xfe) return null;
    return "MPEG audio stream (MP3/AAC)";
  }
  return null;
};

const detectFlv = (dv: DataView): ProbeResult => {
  if (dv.byteLength < 3) return null;
  const sig =
    String.fromCharCode(dv.getUint8(0)) +
    String.fromCharCode(dv.getUint8(1)) +
    String.fromCharCode(dv.getUint8(2));
  return sig === "FLV" ? "FLV video" : null;
};

const detectAvi = (dv: DataView): ProbeResult => {
  if (dv.byteLength < 12) return null;
  const riff = dv.getUint32(0, false);
  const avi = dv.getUint32(8, false);
  if (riff === 0x52494646 && avi === 0x41564920) return "AVI/DivX video (RIFF)";
  return null;
};

const detectAsf = (dv: DataView): ProbeResult => {
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
};

const detectIsoBmff = (dv: DataView): ProbeResult => {
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
};

const detectMpegPs = (dv: DataView): ProbeResult => {
  if (dv.byteLength < 4) return null;
  const sig = dv.getUint32(0, false);
  return sig === 0x000001ba ? "MPEG Program Stream (MPG)" : null;
};

const detectMpegTs = (dv: DataView): ProbeResult => {
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
};

const detectRealMedia = (dv: DataView): ProbeResult => {
  if (dv.byteLength < 4) return null;
  const sig = dv.getUint32(0, false);
  return sig === 0x2e524d46 ? "RealMedia container (RM/RMVB)" : null;
};

const detectMatroska = (dv: DataView): ProbeResult => {
  if (dv.byteLength < 4) return null;
  const sig = dv.getUint32(0, false);
  if (sig !== 0x1a45dfa3) return null;
  return "Matroska/WebM container";
};

const mediaProbes: Array<(dv: DataView) => ProbeResult> = [
  detectFlac,
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
  detectMatroska
];

export { mediaProbes };
