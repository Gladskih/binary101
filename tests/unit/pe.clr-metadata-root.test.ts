"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseClrMetadataRoot } from "../../analyzers/pe/clr/metadata-root.js";
import { MockFile } from "../helpers/mock-file.js";

const encoder = new TextEncoder();
const align4 = (value: number): number => (value + 3) & ~3;
// ECMA-335 II.24.2.1 ("Metadata root"): signature "BSJB" = 0x424A5342.
const CLR_METADATA_SIGNATURE_BSJB = 0x424a5342;
// ECMA-335 II.24.2.2 ("Stream header"): "The name is limited to 32 characters."
const CLR_STREAM_NAME_SPEC_LIMIT = 32;
const CLR_V1_VERSION_BYTES = encoder.encode("v1.0\0");
const CLR_V4_VERSION_BYTES = encoder.encode("v4.0\0");

type MetadataStreamFixture = {
  offset: number;
  size: number;
  name: string;
};

const getStreamHeaderSize = (name: string): number => 8 + align4(name.length + 1);

const measureMetadataRootSize = (
  versionBytes: Uint8Array,
  streams: MetadataStreamFixture[]
): number => align4(16 + versionBytes.length) + 4 + streams.reduce(
  (total, stream) => total + getStreamHeaderSize(stream.name),
  0
);

const createMetadataRootBytes = (
  metaOffset: number,
  metaSize: number,
  versionBytes: Uint8Array,
  declaredStreamCount: number,
  streams: MetadataStreamFixture[],
  signature = CLR_METADATA_SIGNATURE_BSJB
): Uint8Array => {
  const requiredSize = measureMetadataRootSize(versionBytes, streams);
  assert.ok(
    requiredSize <= metaSize,
    `Metadata fixture requires ${requiredSize} bytes, but only ${metaSize} were reserved.`
  );

  const bytes = new Uint8Array(metaOffset + metaSize).fill(0);
  const view = new DataView(bytes.buffer, metaOffset, metaSize);
  let cursor = 0;
  view.setUint32(cursor, signature, true);
  cursor += 4;
  view.setUint16(cursor, 1, true);
  cursor += 2;
  view.setUint16(cursor, 1, true);
  cursor += 2;
  view.setUint32(cursor, 0, true);
  cursor += 4;
  // ECMA-335 II.24.2.1: Length stores x, the null-terminated version string rounded up to 4 bytes.
  view.setUint32(cursor, align4(versionBytes.length), true);
  cursor += 4;
  bytes.set(versionBytes, metaOffset + cursor);
  cursor = align4(cursor + versionBytes.length);
  view.setUint16(cursor, 0, true);
  cursor += 2;
  view.setUint16(cursor, declaredStreamCount, true);
  cursor += 2;

  for (const stream of streams) {
    view.setUint32(cursor, stream.offset, true);
    cursor += 4;
    view.setUint32(cursor, stream.size, true);
    cursor += 4;
    bytes.set(encoder.encode(`${stream.name}\0`), metaOffset + cursor);
    cursor += align4(stream.name.length + 1);
  }

  return bytes;
};

const createSequentialStreams = (streamCount: number): MetadataStreamFixture[] =>
  Array.from({ length: streamCount }, (_, index) => ({
    offset: index * 4,
    size: 4,
    name: `S${index.toString(16)}`
  }));

const parseMetadataFixture = async (
  fileName: string,
  metaOffset: number,
  metaSize: number,
  bytes: Uint8Array
): Promise<{ meta: Awaited<ReturnType<typeof parseClrMetadataRoot>>; issues: string[] }> => {
  const issues: string[] = [];
  const meta = await parseClrMetadataRoot(
    new MockFile(bytes, fileName),
    metaOffset,
    metaSize,
    issues
  );
  return { meta, issues };
};

const hasIssueLike = (issues: string[], pattern: RegExp): boolean =>
  issues.some(issue => pattern.test(issue));

const metadataVersionLengthFieldOffset = 12;
const metadataVersionStringFieldOffset = 16;

const createVersionLengthFixture = (
  metaOffset: number,
  versionBytes: Uint8Array,
  declaredLength: number
): Uint8Array => {
  const metaSize = align4(metadataVersionStringFieldOffset + versionBytes.length) + 4;
  const bytes = createMetadataRootBytes(metaOffset, metaSize, versionBytes, 0, []);
  const view = new DataView(bytes.buffer, metaOffset, metaSize);
  view.setUint32(metadataVersionLengthFieldOffset, declaredLength, true);
  bytes.set(versionBytes, metaOffset + metadataVersionStringFieldOffset);
  return bytes;
};

void test("parseClrMetadataRoot reports unexpected metadata root signatures", async () => {
  const metaOffset = 0x20;
  const metaSize = 0x40;
  const { meta, issues } = await parseMetadataFixture(
    "meta-bad-sig.bin",
    metaOffset,
    metaSize,
    createMetadataRootBytes(metaOffset, metaSize, CLR_V1_VERSION_BYTES, 0, [], 0x11111111)
  );

  assert.strictEqual(meta, null);
  assert.ok(hasIssueLike(issues, /signature/i));
});

void test("parseClrMetadataRoot parses stream headers beyond 0x4000 metadata offsets", async () => {
  const metaOffset = 0x40;
  const versionBytes = new Uint8Array(0x4fd0).fill(0);
  versionBytes.set(encoder.encode("v9.9"));
  const streams = [{ offset: 0x40, size: 0x80, name: "#Strings" }];
  const metaSize = measureMetadataRootSize(versionBytes, streams);
  const { meta, issues } = await parseMetadataFixture(
    "meta-large-header.bin",
    metaOffset,
    metaSize,
    createMetadataRootBytes(metaOffset, metaSize, versionBytes, streams.length, streams)
  );

  assert.ok(meta);
  assert.strictEqual(meta.version, "v9.9");
  assert.strictEqual(meta.streams.length, 1);
  assert.strictEqual(meta.streams[0]?.name, "#Strings");
  assert.deepStrictEqual(issues, []);
});

void test(
  "parseClrMetadataRoot parses every declared stream header without an implementation cap",
  async () => {
    const metaOffset = 0x20;
    const declaredStreamCount = 2049;
    const streams = createSequentialStreams(declaredStreamCount);
    const metaSize = measureMetadataRootSize(CLR_V4_VERSION_BYTES, streams);
    const { meta, issues } = await parseMetadataFixture(
      "meta-many-streams.bin",
      metaOffset,
      metaSize,
      createMetadataRootBytes(
        metaOffset,
        metaSize,
        CLR_V4_VERSION_BYTES,
        declaredStreamCount,
        streams
      )
    );

    assert.ok(meta);
    assert.strictEqual(meta.streamCount, declaredStreamCount);
    assert.strictEqual(meta.streams.length, declaredStreamCount);
    assert.ok(!hasIssueLike(issues, /capped|incomplete/i));
  }
);

void test(
  "parseClrMetadataRoot reports stream names longer than the ECMA-335 32-character limit",
  async () => {
    const metaOffset = 0x20;
    const streamName = "S".repeat(CLR_STREAM_NAME_SPEC_LIMIT + 1);
    const streams = [{ offset: 0x40, size: 0x20, name: streamName }];
    const metaSize = measureMetadataRootSize(CLR_V4_VERSION_BYTES, streams);
    const { meta, issues } = await parseMetadataFixture(
      "meta-stream-name-too-long.bin",
      metaOffset,
      metaSize,
      createMetadataRootBytes(
        metaOffset,
        metaSize,
        CLR_V4_VERSION_BYTES,
        streams.length,
        streams
      )
    );

    assert.ok(meta);
    assert.ok(hasIssueLike(issues, /\b32\b/));
  }
);

void test("parseClrMetadataRoot reports stream sizes that are not multiples of 4", async () => {
  const metaOffset = 0x20;
  const streams = [{ offset: 0x40, size: 3, name: "#US" }];
  const metaSize = measureMetadataRootSize(CLR_V4_VERSION_BYTES, streams);
  const { meta, issues } = await parseMetadataFixture(
    "meta-stream-size-not-aligned.bin",
    metaOffset,
    metaSize,
    createMetadataRootBytes(metaOffset, metaSize, CLR_V4_VERSION_BYTES, streams.length, streams)
  );

  assert.ok(meta);
  assert.ok(hasIssueLike(issues, /multiple of 4/i));
});

void test("parseClrMetadataRoot reports duplicate metadata stream names", async () => {
  const metaOffset = 0x20;
  const streams = [
    { offset: 0x40, size: 0x20, name: "#Strings" },
    { offset: 0x60, size: 0x20, name: "#Strings" }
  ];
  const metaSize = measureMetadataRootSize(CLR_V4_VERSION_BYTES, streams);
  const { meta, issues } = await parseMetadataFixture(
    "meta-duplicate-streams.bin",
    metaOffset,
    metaSize,
    createMetadataRootBytes(metaOffset, metaSize, CLR_V4_VERSION_BYTES, streams.length, streams)
  );

  assert.ok(meta);
  assert.ok(hasIssueLike(issues, /duplicate/i));
});

void test("parseClrMetadataRoot preserves vendor-specific UTF-8 version strings", async () => {
  const metaOffset = 0x20;
  const versionBytes = encoder.encode("V\u00e9ndor CLR\0");
  const metaSize = measureMetadataRootSize(versionBytes, []);
  const { meta, issues } = await parseMetadataFixture(
    "meta-vendor-utf8.bin",
    metaOffset,
    metaSize,
    createMetadataRootBytes(metaOffset, metaSize, versionBytes, 0, [])
  );

  assert.ok(meta);
  assert.strictEqual(meta.version, "V\u00e9ndor CLR");
  assert.deepStrictEqual(issues, []);
});

void test("parseClrMetadataRoot reports version strings that are not null-terminated inside Length", async () => {
  const metaOffset = 0x20;
  const metaSize = 0x20;
  const { meta, issues } = await parseMetadataFixture(
    "meta-version-no-nul.bin",
    metaOffset,
    metaSize,
    createMetadataRootBytes(metaOffset, metaSize, encoder.encode("ABCD"), 0, [])
  );

  assert.ok(meta);
  assert.ok(hasIssueLike(issues, /null|terminator/i));
});

void test("parseClrMetadataRoot reports stream names missing a null terminator", async () => {
  const metaOffset = 0x20;
  const streams = [{ offset: 0x80, size: 4, name: "#~" }];
  const metaSize = 0x100;
  const bytes = createMetadataRootBytes(
    metaOffset,
    metaSize,
    CLR_V4_VERSION_BYTES,
    streams.length,
    streams
  );
  const streamHeaderOffset = align4(16 + CLR_V4_VERSION_BYTES.length) + 4;
  const streamNameOffset = metaOffset + streamHeaderOffset + 8;
  bytes.fill(0x41, streamNameOffset, metaOffset + 0x80);
  bytes.set(encoder.encode("#~AAAAAAAA"), streamNameOffset);
  bytes[metaOffset + 0x80] = 0;

  const { meta, issues } = await parseMetadataFixture(
    "meta-stream-name-no-nul.bin",
    metaOffset,
    metaSize,
    bytes
  );

  assert.ok(meta);
  assert.ok(hasIssueLike(issues, /null|terminator/i));
});

void test("parseClrMetadataRoot accepts the ECMA-335 minimum metadata root size of 0x18 bytes", async () => {
  const metaOffset = 0x20;
  // ECMA-335 II.24.2.1: Length includes the terminating NUL and is rounded up to a 4-byte boundary.
  // The smallest valid version string is therefore just "\0", which makes the zero-stream metadata root 0x18 bytes.
  const versionBytes = new Uint8Array([0]);
  const metaSize = measureMetadataRootSize(versionBytes, []);
  const { meta, issues } = await parseMetadataFixture(
    "meta-min-root.bin",
    metaOffset,
    metaSize,
    createMetadataRootBytes(metaOffset, metaSize, versionBytes, 0, [])
  );

  assert.ok(meta);
  assert.strictEqual(meta.version, "");
  assert.strictEqual(meta.streamCount, 0);
  assert.deepStrictEqual(issues, []);
});

void test("parseClrMetadataRoot reports version Length fields of zero", async () => {
  const metaOffset = 0x20;
  // ECMA-335 II.24.2.1: Length stores the allocated byte count for the version string and cannot be zero.
  const bytes = createVersionLengthFixture(metaOffset, Uint8Array.of(0), 0);
  const metaSize = bytes.length - metaOffset;

  const { meta, issues } = await parseMetadataFixture(
    "meta-version-length-zero.bin",
    metaOffset,
    metaSize,
    bytes
  );

  assert.ok(meta);
  assert.ok(hasIssueLike(issues, /version|length/i));
});

void test("parseClrMetadataRoot reports version Length fields that are not 4-byte aligned", async () => {
  const metaOffset = 0x20;
  const versionBytes = encoder.encode("v4.0\0");
  // ECMA-335 II.24.2.1: Length is rounded up to a 4-byte boundary, so a 5-byte declaration is invalid.
  const declaredLength = versionBytes.length;
  const bytes = createVersionLengthFixture(metaOffset, versionBytes, declaredLength);
  const metaSize = bytes.length - metaOffset;

  const { meta, issues } = await parseMetadataFixture(
    "meta-version-length-misaligned.bin",
    metaOffset,
    metaSize,
    bytes
  );

  assert.ok(meta);
  assert.ok(hasIssueLike(issues, /version|length|multiple of 4|aligned/i));
});

void test("parseClrMetadataRoot reports non-ASCII metadata stream names", async () => {
  const metaOffset = 0x20;
  const streams = [{ offset: 0x20, size: Uint32Array.BYTES_PER_ELEMENT, name: "#A" }];
  const metaSize = measureMetadataRootSize(CLR_V4_VERSION_BYTES, streams);
  const bytes = createMetadataRootBytes(
    metaOffset,
    metaSize,
    CLR_V4_VERSION_BYTES,
    streams.length,
    streams
  );
  const firstStreamHeaderOffset = align4(metadataVersionStringFieldOffset + CLR_V4_VERSION_BYTES.length) + 4;
  // ECMA-335 II.24.2.2: stream names are null-terminated ASCII, so 0xe9 must be rejected.
  bytes[metaOffset + firstStreamHeaderOffset + 8 + 1] = 0xe9;

  const { meta, issues } = await parseMetadataFixture(
    "meta-stream-name-non-ascii.bin",
    metaOffset,
    metaSize,
    bytes
  );

  assert.ok(meta);
  assert.ok(hasIssueLike(issues, /ascii|stream name/i));
});
