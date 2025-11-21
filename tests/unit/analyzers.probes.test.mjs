"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { probeByMagic, probeTextLike } from "../../analyzers/probes.js";

const dvFrom = bytes => new DataView(new Uint8Array(bytes).buffer);
const ascii = text => [...Buffer.from(text, "ascii")];

test("probeByMagic identifies common signatures", () => {
  assert.strictEqual(
    probeByMagic(dvFrom([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])),
    "PNG image"
  );

  assert.strictEqual(
    probeByMagic(
      dvFrom([0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x37]) // "%PDF-1.7"
    ),
    "PDF document"
  );

  assert.strictEqual(
    probeByMagic(dvFrom([0x50, 0x4b, 0x03, 0x04])), // PK..
    "ZIP archive (PK-based, e.g. Office, JAR, APK)"
  );

  assert.strictEqual(
    probeByMagic(dvFrom([0x47, 0x49, 0x46, 0x38, 0x39, 0x61])), // GIF89a
    "GIF image"
  );
});

test("probeByMagic covers varied archive and container signatures", () => {
  const sevenZip = [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0x00, 0x00];
  assert.strictEqual(probeByMagic(dvFrom(sevenZip)), "7z archive");

  const rar = [...Buffer.from("Rar!\u001a\u0007", "binary"), 0x00];
  assert.strictEqual(probeByMagic(dvFrom(rar)), "RAR archive");

  const asfGuid = [
    0x30, 0x26, 0xb2, 0x75, 0x8e, 0x66, 0xcf, 0x11,
    0xa6, 0xd9, 0x00, 0xaa, 0x00, 0x62, 0xce, 0x6c
  ];
  assert.strictEqual(probeByMagic(dvFrom(asfGuid)), "ASF container (WMA/WMV)");

  const isoBmff = new Uint8Array(12);
  const isoDv = new DataView(isoBmff.buffer);
  isoDv.setUint32(4, 0x66747970, false); // "ftyp"
  isoDv.setUint32(8, 0x6d703432, false); // "mp42"
  assert.strictEqual(probeByMagic(isoDv), "MP4/QuickTime container (ISO-BMFF)");

  const tarBytes = new Uint8Array(300);
  tarBytes.set([0x75, 0x73, 0x74, 0x61, 0x72], 257); // "ustar"
  assert.strictEqual(probeByMagic(new DataView(tarBytes.buffer)), "TAR archive");
});

test("probeByMagic safely handles empty and non-matching buffers", () => {
  assert.strictEqual(probeByMagic(dvFrom([])), null);
  const zeros = new Uint8Array(400).fill(0);
  assert.strictEqual(probeByMagic(new DataView(zeros.buffer)), null);
});

test("probeByMagic detects additional compression formats", () => {
  const cases = [
    { bytes: [0x1f, 0x8b, 0x08, 0x00], label: "gzip compressed data" },
    { bytes: ascii("BZh"), label: "bzip2 compressed data" },
    { bytes: [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00], label: "XZ compressed data" },
    { bytes: [0x04, 0x22, 0x4d, 0x18], label: "LZ4 frame" },
    { bytes: [0x28, 0xb5, 0x2f, 0xfd, 0x00], label: "Zstandard compressed data (zstd)" },
    { bytes: ascii("MSCF"), label: "Microsoft Cabinet archive (CAB)" }
  ];
  cases.forEach(({ bytes, label }) => {
    assert.strictEqual(probeByMagic(dvFrom(bytes)), label);
  });
});

test("probeByMagic detects image and document headers", () => {
  const isoBase = new Uint8Array(12);
  const isoView = new DataView(isoBase.buffer);
  isoView.setUint32(4, 0x66747970, false); // ftyp
  isoView.setUint32(8, 0x68656963, false); // heic

  const tests = [
    {
      bytes: [0xff, 0xd8, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x00, 0x00, 0x00, 0x00],
      label: "JPEG image (JFIF)"
    },
    {
      bytes: [0xff, 0xd8, 0x45, 0x78, 0x69, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00],
      label: "JPEG image (EXIF)"
    },
    { bytes: [0x42, 0x4d, 0x00, 0x00], label: "BMP bitmap image" },
    { bytes: [0x49, 0x49, 0x2a, 0x00], label: "TIFF image" },
    {
      bytes: [...ascii("RIFF"), 0x00, 0x00, 0x00, 0x00, ...ascii("WEBP")],
      label: "WebP image"
    },
    { bytes: [0x00, 0x00, 0x01, 0x00], label: "ICO/CUR icon image" },
    {
      bytes: [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1],
      label: "Microsoft Compound File (e.g. Office 97-2003, MSI)"
    },
    { bytes: isoBase, label: "HEIF/HEIC image (ISO-BMFF)" },
    {
      bytes: (() => {
        const pdb = new Uint8Array(64).fill(0);
        pdb.set(ascii("Microsoft C/C++ MSF 7.00 Program Database"));
        return pdb;
      })(),
      label: "Microsoft PDB debug symbols"
    }
  ];
  tests.forEach(({ bytes, label }) => {
    assert.strictEqual(probeByMagic(dvFrom(bytes)), label);
  });
});

test("probeByMagic detects audio and video container signatures", () => {
  const tsBytes = new Uint8Array(188 * 3).fill(0);
  tsBytes[0] = 0x47;
  tsBytes[188] = 0x47;
  tsBytes[376] = 0x47;

  const cases = [
    { bytes: ascii("fLaC"), label: "FLAC audio" },
    { bytes: ascii("OggS"), label: "Ogg container (Vorbis/Opus/FLAC)" },
    { bytes: [...ascii("RIFF"), 0, 0, 0, 0, ...ascii("WAVE")], label: "WAVE audio (RIFF)" },
    { bytes: [...ascii("FORM"), 0, 0, 0, 0, ...ascii("AIFF")], label: "AIFF/AIFFC audio" },
    { bytes: ascii("MThd"), label: "MIDI audio" },
    { bytes: ascii("#!AMR\n"), label: "AMR audio" },
    { bytes: [0x0b, 0x77], label: "Dolby AC-3 audio" },
    { bytes: [0x7f, 0xfe, 0x80, 0x01], label: "DTS audio" },
    { bytes: ascii("ID3\u0004"), label: "MPEG audio with ID3 tag (MP3/AAC)" },
    { bytes: ascii("FLV"), label: "FLV video" },
    { bytes: [...ascii("RIFF"), 0, 0, 0, 0, ...ascii("AVI ")], label: "AVI/DivX video (RIFF)" },
    { bytes: [0x00, 0x00, 0x01, 0xba], label: "MPEG Program Stream (MPG)" },
    { bytes: tsBytes, label: "MPEG Transport Stream (TS)" },
    { bytes: [0x2e, 0x52, 0x4d, 0x46], label: "RealMedia container (RM/RMVB)" },
    { bytes: [0x1a, 0x45, 0xdf, 0xa3], label: "Matroska/WebM container" }
  ];
  cases.forEach(({ bytes, label }) => {
    assert.strictEqual(probeByMagic(dvFrom(bytes)), label);
  });
});

test("probeByMagic detects disk images and miscellaneous binary formats", () => {
  const tar = new Uint8Array(300).fill(0);
  tar.set(ascii("ustar"), 257);

  const iso = new Uint8Array(0x8006).fill(0);
  iso.set(ascii("CD001"), 0x8001);

  const djvu = [...ascii("AT&TFORM"), 0, 0, 0, 0, ...ascii("DJVU")];

  const cases = [
    { bytes: tar, label: "TAR archive" },
    { bytes: ascii("SQLite format 3\0"), label: "SQLite 3.x database" },
    { bytes: [0xca, 0xfe, 0xba, 0xbe], label: "Java class file" },
    { bytes: iso, label: "ISO-9660 CD/DVD image (ISO)" },
    { bytes: djvu, label: "DjVu document" },
    { bytes: [0x0a, 0x0d, 0x0d, 0x0a], label: "PCAP-NG capture file" },
    { bytes: [0xa1, 0xb2, 0xc3, 0xd4], label: "PCAP capture file" },
    { bytes: [0x4c, 0x00, 0x00, 0x00], label: "Windows shortcut (.lnk)" },
    { bytes: [0x00, 0x61, 0x73, 0x6d], label: "WebAssembly binary (WASM)" },
    { bytes: ascii("dex\n035\0"), label: "Android DEX bytecode" },
    { bytes: [0x3f, 0x5f, 0x03, 0x00], label: "Windows Help file (HLP)" }
  ];
  cases.forEach(({ bytes, label }) => {
    assert.strictEqual(probeByMagic(dvFrom(bytes)), label);
  });
});

test("probeTextLike classifies plain text and HTML-like payloads", () => {
  const html = "<!doctype html><html><body>Hello</body></html>";
  const htmlDv = dvFrom([...Buffer.from(html, "utf-8")]);
  assert.strictEqual(probeTextLike(htmlDv), "HTML document");

  const text = "plain text without special markers";
  const textDv = dvFrom([...Buffer.from(text, "utf-8")]);
  assert.strictEqual(probeTextLike(textDv), "Text file");
});

test("probeTextLike recognizes XML, SVG, JSON and FB2 markers", () => {
  const svg = '<?xml version="1.0"?><svg><rect/></svg>';
  const svgDv = dvFrom([...Buffer.from(svg, "utf-8")]);
  assert.strictEqual(probeTextLike(svgDv), "SVG image (XML)");

  const fb2 = '<?xml version="1.0" encoding="UTF-8"?><FictionBook><body/></FictionBook>';
  const fb2Dv = dvFrom([...Buffer.from(fb2, "utf-8")]);
  assert.strictEqual(probeTextLike(fb2Dv), "FictionBook e-book (FB2)");

  const json = '{ "hello": "world" }';
  const jsonDv = dvFrom([...Buffer.from(json, "utf-8")]);
  assert.strictEqual(probeTextLike(jsonDv), "JSON data");
});

test("probeTextLike detects shebang, XML, RTF and rejects binary blobs", () => {
  const shebang = "#!/usr/bin/env node\nconsole.log('hi');";
  assert.strictEqual(probeTextLike(dvFrom([...Buffer.from(shebang, "utf-8")])), "Text script (shebang)");

  const plainXml = '<?xml version="1.0"?><root></root>';
  assert.strictEqual(probeTextLike(dvFrom([...Buffer.from(plainXml, "utf-8")])), "XML document");

  const rtf = "{\\rtf1\\ansi\\deff0{\\fonttbl}}";
  assert.strictEqual(probeTextLike(dvFrom([...Buffer.from(rtf, "utf-8")])), "RTF document");

  const binary = new Uint8Array([0x00, 0xff, 0x10, 0x00]);
  assert.strictEqual(probeTextLike(new DataView(binary.buffer)), null);
});
