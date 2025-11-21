"use strict";

import { MockFile } from "../helpers/mock-file.mjs";

const encoder = new TextEncoder();

const buildHeader = (name, sizeOctal, checksumPlaceholder = "        ") => {
  const block = new Uint8Array(512).fill(0);
  const write = (offset, text, length) => {
    const bytes = encoder.encode(text);
    block.set(bytes.slice(0, length), offset);
  };
  write(0, name, 100);
  write(124, sizeOctal, 12);
  write(148, checksumPlaceholder, 8);
  write(257, "ustar", 6);
  write(263, "00", 2);
  return block;
};

export const createTarWithBadChecksum = () => {
  const header = buildHeader("file.txt", "00000000010");
  // incorrect checksum (all spaces preserved)
  const end = new Uint8Array(512).fill(0);
  const tar = new Uint8Array(header.length + end.length);
  tar.set(header, 0);
  tar.set(end, header.length);
  return new MockFile(tar, "bad-checksum.tar", "application/x-tar");
};

export const createTarWithShortFile = () => {
  const header = buildHeader("short.txt", "00000000001");
  let sum = 0;
  for (let i = 0; i < header.length; i += 1) sum += header[i];
  const checksumOctal = sum.toString(8).padStart(6, "0") + "\0 ";
  const fixed = header.slice();
  const checksumBytes = encoder.encode(checksumOctal);
  fixed.set(checksumBytes, 148);
  const payload = new Uint8Array(1); // but none of the required padding
  const tar = new Uint8Array(fixed.length + payload.length + 512);
  tar.set(fixed, 0);
  tar.set(payload, fixed.length);
  return new MockFile(tar, "short-file.tar", "application/x-tar");
};
