"use strict";

import { MockFile } from "../helpers/mock-file.mjs";
export { createPeWithSectionAndIat, createPeFile } from "./sample-files-pe.mjs";

const fromBase64 = base64 => new Uint8Array(Buffer.from(base64, "base64"));
const encoder = new TextEncoder();

export const createPngFile = () =>
  new MockFile(
    fromBase64("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/5+hHgAFgwJ/l7nnMgAAAABJRU5ErkJggg=="),
    "sample.png",
    "image/png"
  );

export const createGifFile = () =>
  new MockFile(
    fromBase64("R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw=="),
    "sample.gif",
    "image/gif"
  );

export const createJpegFile = () =>
  new MockFile(
    fromBase64("/9j/4AAQSkZJRgABAQEAYABgAAD/2wCEAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQH/wAALCAABAAEBAREA/8QAFQABAQAAAAAAAAAAAAAAAAAAAAj/xAAUEAEAAAAAAAAAAAAAAAAAAAAA/9oADAMBAAIQAxAAAAH/AP/EABQQAQAAAAAAAAAAAAAAAAAAAD/2gAIAQEAAAAl/8QAFBEBAAAAAAAAAAAAAAAAAAAAAP/aAAgBAwEBPwE//8QAFBEBAAAAAAAAAAAAAAAAAAAAAP/aAAgBAgEBPwE//8QAFBABAAAAAAAAAAAAAAAAAAAAAP/aAAgBAwEBPwE//9k="),
    "sample.jpg",
    "image/jpeg"
  );

export const createWebpFile = () =>
  new MockFile(
    fromBase64("UklGRiIAAABXRUJQVlA4ICAAAAAwAQCdASoBAAEAAQAcJaQAA3AA/vuUAAA="),
    "sample.webp",
    "image/webp"
  );

export const createFb2File = () => {
  const xml = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    "<FictionBook>",
    "<description><title-info><book-title>Example</book-title></title-info></description>",
    "<body><section><p>Hello world</p></section></body>",
    "</FictionBook>"
  ].join("\n");
  return new MockFile(encoder.encode(xml), "sample.fb2", "text/xml");
};

const formatOffset = value => value.toString(8).padStart(7, "0") + "\0";
const writeString = (buffer, text, offset, length) => {
  const bytes = encoder.encode(text);
  const max = Math.min(bytes.length, length);
  buffer.set(bytes.slice(0, max), offset);
};

export const createTarFile = () => {
  const blockSize = 512;
  const header = new Uint8Array(blockSize).fill(0);
  writeString(header, "hello.txt", 0, 100);
  writeString(header, "0000777\0", 100, 8);
  writeString(header, "0000000\0", 108, 8);
  writeString(header, "0000000\0", 116, 8);
  writeString(header, "00000000000\0", 124, 12);
  writeString(header, "00000000000\0", 136, 12);
  // Checksum placeholder of eight spaces
  for (let i = 148; i < 156; i += 1) header[i] = 0x20;
  writeString(header, "0", 156, 1);
  writeString(header, "ustar", 257, 6);
  writeString(header, "00", 263, 2);
  writeString(header, "user", 265, 32);
  writeString(header, "group", 297, 32);

  let sum = 0;
  for (let i = 0; i < header.length; i += 1) sum += header[i];
  const checksum = formatOffset(sum);
  writeString(header, checksum, 148, 8);

  const endBlock = new Uint8Array(blockSize).fill(0);
  const tarBytes = new Uint8Array(blockSize * 2);
  tarBytes.set(header, 0);
  tarBytes.set(endBlock, blockSize);
  return new MockFile(tarBytes, "sample.tar", "application/x-tar");
};

export const createZipFile = () =>
  new MockFile(
    new Uint8Array([
      0x50, 0x4b, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ]),
    "empty.zip",
    "application/zip"
  );

export const createPngWithIhdr = () =>
  new MockFile(
    fromBase64("iVBORw0KGgoAAAANSUhEUgAAAAIAAAACCAIAAAB7GkOtAAAADUlEQVR42mNk+M9QDwADaQH4UNIAMwAAAABJRU5ErkJggg=="),
    "two-by-two.png",
    "image/png"
  );

export const createPdfFile = () => {
  const header = "%PDF-1.4\n";
  const obj1 = "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n";
  const obj2 = "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n";
  const obj3 =
    "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R >>\nendobj\n";
  const obj4 = "4 0 obj\n<< /Length 11 >>\nstream\nHello World\nendstream\nendobj\n";

  const offsets = [];
  let cursor = 0;
  const add = segment => {
    offsets.push(cursor);
    cursor += Buffer.byteLength(segment, "latin1");
    return segment;
  };

  const body = [add(header), add(obj1), add(obj2), add(obj3), add(obj4)].join("");
  const xrefOffset = cursor;
  const pad = value => value.toString().padStart(10, "0");
  const xref =
    "xref\n0 5\n" +
    `${pad(0)} 65535 f \n` +
    `${pad(offsets[1])} 00000 n \n` +
    `${pad(offsets[2])} 00000 n \n` +
    `${pad(offsets[3])} 00000 n \n` +
    `${pad(offsets[4])} 00000 n \n`;
  const trailer = `trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n${xrefOffset}\n%%EOF\n`;
  const pdfText = body + xref + trailer;
  return new MockFile(encoder.encode(pdfText), "sample.pdf", "application/pdf");
};

export const createFb2TextOnlyFile = createFb2File;

const buildElf64File = () => {
  const headerSize = 64;
  const phSize = 56;
  const shSize = 64;
  const phoff = headerSize;
  const shoff = phoff + phSize;
  const shstrOffset = shoff + shSize * 2;
  const shstrContent = encoder.encode("\0.shstrtab\0");
  const totalSize = shstrOffset + shstrContent.length;
  const bytes = new Uint8Array(totalSize).fill(0);
  const dv = new DataView(bytes.buffer);
  // e_ident
  dv.setUint32(0, 0x7f454c46, false); // ELF
  dv.setUint8(4, 2); // 64-bit
  dv.setUint8(5, 1); // little endian
  dv.setUint8(6, 1); // version
  // e_type, e_machine, e_version
  dv.setUint16(16, 2, true); // executable
  dv.setUint16(18, 0x3e, true); // x86-64
  dv.setUint32(20, 1, true);
  dv.setBigUint64(24, 0x400000n, true); // entry
  dv.setBigUint64(32, BigInt(phoff), true);
  dv.setBigUint64(40, BigInt(shoff), true);
  dv.setUint32(48, 0, true); // flags
  dv.setUint16(52, headerSize, true);
  dv.setUint16(54, phSize, true);
  dv.setUint16(56, 1, true);
  dv.setUint16(58, shSize, true);
  dv.setUint16(60, 2, true); // shnum
  dv.setUint16(62, 1, true); // shstrndx
  // Program header (single load segment)
  dv.setUint32(phoff + 0, 1, true); // PT_LOAD
  dv.setUint32(phoff + 4, 5, true); // flags R+X
  dv.setBigUint64(phoff + 8, 0n, true); // offset
  dv.setBigUint64(phoff + 16, 0x400000n, true); // vaddr
  dv.setBigUint64(phoff + 24, 0x400000n, true); // paddr
  dv.setBigUint64(phoff + 32, BigInt(totalSize), true); // filesz
  dv.setBigUint64(phoff + 40, BigInt(totalSize), true); // memsz
  dv.setBigUint64(phoff + 48, 0x1000n, true); // align
  // Section header 0 (null)
  // Section header 1 (.shstrtab)
  const sh1 = shoff + shSize;
  dv.setUint32(sh1 + 0, 1, true); // name offset in shstrtab
  dv.setUint32(sh1 + 4, 3, true); // type: STRTAB
  dv.setBigUint64(sh1 + 8, 0n, true); // flags
  dv.setBigUint64(sh1 + 16, 0n, true); // addr
  dv.setBigUint64(sh1 + 24, BigInt(shstrOffset), true); // offset
  dv.setBigUint64(sh1 + 32, BigInt(shstrContent.length), true); // size
  dv.setUint32(sh1 + 40, 0, true); // link
  dv.setUint32(sh1 + 44, 0, true); // info
  dv.setBigUint64(sh1 + 48, 1n, true); // addralign
  dv.setBigUint64(sh1 + 56, 0n, true); // entsize

  bytes.set(shstrContent, shstrOffset);
  return bytes;
};

export const createElfFile = () =>
  new MockFile(buildElf64File(), "sample.elf", "application/x-elf");

export const createMp3File = () => {
  const versionBits = 0x3;
  const layerBits = 0x1;
  const bitrateIndex = 0x9; // 128 kbps
  const sampleRateIndex = 0x0; // 44100
  const header =
    (0x7ff << 21) |
    (versionBits << 19) |
    (layerBits << 17) |
    (1 << 16) | // no CRC
    (bitrateIndex << 12) |
    (sampleRateIndex << 10) |
    (0 << 9) | // padding
    (0 << 6) | // channel mode stereo
    (0 << 4) |
    (0 << 2) |
    0;
  const frameLength = Math.floor((1152 * 128000) / (8 * 44100));
  const totalLength = frameLength * 2;
  const bytes = new Uint8Array(totalLength).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, header, false);
  view.setUint32(frameLength, header, false);
  return new MockFile(bytes, "sample.mp3", "audio/mpeg");
};

export const createSevenZipFile = () => {
  const header = new Uint8Array(32).fill(0);
  const sig = [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c];
  header.set(sig, 0);
  header[6] = 0; // version major
  header[7] = 4; // version minor
  // next header located immediately after the start header
  const view = new DataView(header.buffer);
  view.setBigUint64(12, 0n, true); // next header offset
  view.setBigUint64(20, 2n, true); // next header size
  const nextHeader = new Uint8Array([0x01, 0x00]); // minimal header + terminator
  const combined = new Uint8Array(header.length + nextHeader.length);
  combined.set(header, 0);
  combined.set(nextHeader, header.length);
  return new MockFile(combined, "sample.7z", "application/x-7z-compressed");
};
