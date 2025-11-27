"use strict";

import { MockFile } from "../helpers/mock-file.js";

const TEXT_ENCODER = new TextEncoder();
const TAR_BLOCK_SIZE = 512;

type TarHeaderOptions = {
  name?: string;
  mode?: number;
  uid?: number;
  gid?: number;
  size?: number;
  mtime?: number;
  checksum?: number;
  typeFlag?: string;
  linkName?: string;
  magic?: string;
  version?: string;
  uname?: string;
  gname?: string;
  devMajor?: number;
  devMinor?: number;
  prefix?: string;
};

export const calculateChecksum = (headerBytes: Uint8Array): number => {
  let sum = 0;
  for (let i = 0; i < TAR_BLOCK_SIZE; i += 1) {
    if (i >= 148 && i < 156) {
      sum += 0x20; // Checksum field is treated as spaces for calculation
    } else {
      sum += headerBytes[i] ?? 0;
    }
  }
  return sum;
};

const writeString = (buffer: Uint8Array, text: string, offset: number, length: number): void => {
  const bytes = TEXT_ENCODER.encode(text);
  const max = Math.min(bytes.length, length);
  buffer.set(bytes.slice(0, max), offset);
};

export const writeOctal = (
  buffer: Uint8Array,
  value: number,
  offset: number,
  length: number
): void => {
  const octalString = value.toString(8).padStart(length - 1, "0");
  writeString(buffer, octalString, offset, length - 1);
  buffer[offset + length - 1] = 0; // Null terminate
};

type TarEntry = TarHeaderOptions & {
  content?: string;
  paxHeader?: string;
  longName?: string;
  longLink?: string;
};

export const buildTarHeader = (opts: TarHeaderOptions = {}) => {
  const {
    name = "",
    mode = 0o644,
    uid = 0,
    gid = 0,
    size = 0,
    mtime = 0,
    checksum = 0, // Will be calculated if not provided
    typeFlag = "0", // Regular file
    linkName = "",
    magic = "ustar",
    version = "00",
    uname = "user",
    gname = "group",
    devMajor = 0,
    devMinor = 0,
    prefix = ""
  } = opts;

  const header = new Uint8Array(TAR_BLOCK_SIZE).fill(0);

  writeString(header, name, 0, 100);
  writeOctal(header, mode, 100, 8);
  writeOctal(header, uid, 108, 8);
  writeOctal(header, gid, 116, 8);
  writeOctal(header, size, 124, 12);
  writeOctal(header, mtime, 136, 12);
  // Checksum field placeholder (8 spaces)
  for (let i = 148; i < 156; i += 1) header[i] = 0x20;

  writeString(header, typeFlag, 156, 1);
  writeString(header, linkName, 157, 100);
  writeString(header, magic, 257, 6);
  writeString(header, version, 263, 2);
  writeString(header, uname, 265, 32);
  writeString(header, gname, 297, 32);
  writeOctal(header, devMajor, 329, 8);
  writeOctal(header, devMinor, 337, 8);
  writeString(header, prefix, 345, 155);

  const finalChecksum = checksum || calculateChecksum(header);
  writeOctal(header, finalChecksum, 148, 8);

  return header;
};

export const createTarFileWithEntries = (
  entries: TarEntry[],
  options: { appendZeroBlocks?: number; unalignedFileSize?: number } = {}
): MockFile => {
  const { appendZeroBlocks = 2, unalignedFileSize = 0 } = options;
  const tarBlocks: Uint8Array[] = [];

  for (const entry of entries) {
    // Handle PAX Global/Extended headers
    if (entry.paxHeader) {
      const paxData = entry.paxHeader;
      const paxSize = TEXT_ENCODER.encode(paxData).byteLength;
      const paxHeaderOpts = {
        name: entry.name || "PaxHeader",
        size: paxSize,
        typeFlag: entry.typeFlag || "x", // 'x' for extended, 'g' for global
        magic: "ustar",
        version: "00",
      };
      const paxHeaderBlock = buildTarHeader(paxHeaderOpts);
      tarBlocks.push(paxHeaderBlock);
      const paxContentBlock = new Uint8Array(Math.ceil(paxSize / TAR_BLOCK_SIZE) * TAR_BLOCK_SIZE).fill(0);
      TEXT_ENCODER.encodeInto(paxData, paxContentBlock);
      tarBlocks.push(paxContentBlock);
    }

    // Handle LongLink/LongName (L/K typeflags)
    if (entry.longName) {
      const longNameBytes = TEXT_ENCODER.encode(entry.longName + "\0");
      const longNameSize = longNameBytes.byteLength;
      const longNameHeaderOpts = {
        name: "././@LongLink", // Standard for GNU long name
        size: longNameSize,
        typeFlag: "L",
        magic: "ustar",
        version: "00",
      };
      const longNameHeaderBlock = buildTarHeader(longNameHeaderOpts);
      tarBlocks.push(longNameHeaderBlock);
      const longNameContentBlock = new Uint8Array(Math.ceil(longNameSize / TAR_BLOCK_SIZE) * TAR_BLOCK_SIZE).fill(0);
      longNameContentBlock.set(longNameBytes);
      tarBlocks.push(longNameContentBlock);
    }
    
    if (entry.longLink) {
      const longLinkBytes = TEXT_ENCODER.encode(entry.longLink + "\0");
      const longLinkSize = longLinkBytes.byteLength;
      const longLinkHeaderOpts = {
        name: "././@LongLink", // Standard for GNU long link
        size: longLinkSize,
        typeFlag: "K",
        magic: "ustar",
        version: "00",
      };
      const longLinkHeaderBlock = buildTarHeader(longLinkHeaderOpts);
      tarBlocks.push(longLinkHeaderBlock);
      const longLinkContentBlock = new Uint8Array(Math.ceil(longLinkSize / TAR_BLOCK_SIZE) * TAR_BLOCK_SIZE).fill(0);
      longLinkContentBlock.set(longLinkBytes);
      tarBlocks.push(longLinkContentBlock);
    }

    const contentBytes = TEXT_ENCODER.encode(entry.content || "");
    const contentSize = contentBytes.byteLength;
    const headerOpts = {
      name: entry.name,
      mode: entry.mode,
      uid: entry.uid,
      gid: entry.gid,
      size: contentSize,
      mtime: entry.mtime,
      typeFlag: entry.typeFlag,
      linkName: entry.linkName,
      magic: entry.magic,
      version: entry.version,
      uname: entry.uname,
      gname: entry.gname,
      devMajor: entry.devMajor,
      devMinor: entry.devMinor,
      prefix: entry.prefix
    };
    const headerBlock = buildTarHeader(headerOpts);
    tarBlocks.push(headerBlock);

    if (contentSize > 0) {
      const dataBlockCount = Math.ceil(contentSize / TAR_BLOCK_SIZE);
      const dataBlocks = new Uint8Array(dataBlockCount * TAR_BLOCK_SIZE).fill(0);
      dataBlocks.set(contentBytes);
      tarBlocks.push(dataBlocks);
    }
  }

  // Append zero blocks for termination
  for (let i = 0; i < appendZeroBlocks; i += 1) {
    tarBlocks.push(new Uint8Array(TAR_BLOCK_SIZE).fill(0));
  }

  const totalLength = tarBlocks.reduce((sum, block) => sum + block.byteLength, 0);
  const tarBytes = new Uint8Array(totalLength + unalignedFileSize);

  let offset = 0;
  for (const block of tarBlocks) {
    tarBytes.set(block, offset);
    offset += block.byteLength;
  }

  return new MockFile(tarBytes, "custom.tar", "application/x-tar");
};

// Existing fixtures (adapted to use buildTarHeader where applicable)
export const createTarWithBadChecksum = () => {
  // Create a valid TAR header but then modify the checksum to be incorrect
  const header = buildTarHeader({ name: "file.txt", size: 0 });
  // Now corrupt the checksum field by overwriting it with incorrect value
  writeOctal(header, 9999, 148, 8); // Write an incorrect checksum
  
  const endBlock = new Uint8Array(TAR_BLOCK_SIZE).fill(0);
  const tar = new Uint8Array(TAR_BLOCK_SIZE * 2);
  tar.set(header, 0);
  tar.set(endBlock, TAR_BLOCK_SIZE);
  return new MockFile(tar, "bad-checksum.tar", "application/x-tar");
};

export const createTarWithShortFile = () => {
  // Create a header that declares size larger than available data
  const header = buildTarHeader({ name: "short.txt", size: 1024 }); // Declare 1024 bytes
  // Create a TAR with only the header and one zero block
  // The data should be 2 blocks (1024 bytes = 2 * 512) but we only provide 1 block
  const dataBlock = new Uint8Array(TAR_BLOCK_SIZE);
  dataBlock.fill(0xAA); // Fill with pattern to show partial data
  const endBlock = new Uint8Array(TAR_BLOCK_SIZE).fill(0);
  
  const tar = new Uint8Array(TAR_BLOCK_SIZE * 3);
  tar.set(header, 0);
  tar.set(dataBlock, TAR_BLOCK_SIZE);
  tar.set(endBlock, TAR_BLOCK_SIZE * 2);
  return new MockFile(tar, "short-file.tar", "application/x-tar");
};
