import { createFileRangeReader } from "../../analyzers/file-range-reader.js";
import { ElfRelocationStream } from "../../analyzers/elf/relocation-stream.js";
import { relocationFixture, relocationStorage } from "./elf-relocations.js";

export const encodeUnsigned = (value: bigint): number[] => {
  const bytes: number[] = [];
  let remaining = value;
  do {
    bytes.push(Number(remaining & 0x7fn));
    remaining >>= 7n;
    if (remaining) bytes[bytes.length - 1]! |= 0x80;
  } while (remaining);
  return bytes;
};

export const encodeSigned = (value: bigint): number[] => {
  const bytes: number[] = [];
  let remaining = value;
  let complete = false;
  while (!complete) {
    const byte = Number(remaining & 0x7fn);
    remaining >>= 7n;
    complete = remaining === 0n && !(byte & 0x40) || remaining === -1n && (byte & 0x40) !== 0;
    bytes.push(complete ? byte : byte | 0x80);
  }
  return bytes;
};

export const packedRelocationFixture = (bytes: number[], bits: 32 | 64 = 64,
  order: "little" | "big" = "little") => {
  const fixture = relocationFixture(bits, order);
  fixture.bytes.set(bytes, relocationStorage.records);
  const reader = createFileRangeReader(fixture.file(), 0, fixture.bytes.length);
  return { ...fixture, reader,
    stream: new ElfRelocationStream(reader, relocationStorage.records, bytes.length) };
};

export const androidRelocationFixture = (values: bigint[], bits: 32 | 64 = 64,
  order: "little" | "big" = "little") =>
  packedRelocationFixture([65, 80, 83, 50, ...values.flatMap(encodeSigned)], bits, order);
