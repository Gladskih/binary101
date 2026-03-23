"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseOptionalHeaderAndDirectories } from "../../analyzers/pe/core-headers.js";
import { MockFile } from "../helpers/mock-file.js";

const PE32_OPTIONAL_HEADER_MAGIC = 0x10b;

void test("parseOptionalHeaderAndDirectories preserves data directories beyond index 15", async () => {
  const dataDirectoryCount = 17;
  const optionalHeaderSize = 0x60 + dataDirectoryCount * 8;
  const fileBytes = new Uint8Array(24 + optionalHeaderSize).fill(0);
  const view = new DataView(fileBytes.buffer);
  const optionalHeaderOffset = 24;
  const dataDirectoryOffset = optionalHeaderOffset + 0x60;

  view.setUint16(optionalHeaderOffset, PE32_OPTIONAL_HEADER_MAGIC, true);
  view.setUint32(optionalHeaderOffset + 28, 0x00400000, true); // ImageBase
  view.setUint32(optionalHeaderOffset + 32, 0x1000, true); // SectionAlignment
  view.setUint32(optionalHeaderOffset + 36, 0x0200, true); // FileAlignment
  view.setUint32(optionalHeaderOffset + 56, 0x2000, true); // SizeOfImage
  view.setUint32(optionalHeaderOffset + 60, 0x0200, true); // SizeOfHeaders
  view.setUint32(optionalHeaderOffset + 92, dataDirectoryCount, true); // NumberOfRvaAndSizes
  view.setUint32(dataDirectoryOffset + 16 * 8, 0x13572468, true);
  view.setUint32(dataDirectoryOffset + 16 * 8 + 4, 0x24681357, true);

  const parsed = await parseOptionalHeaderAndDirectories(
    new MockFile(fileBytes, "extra-data-directories.bin"),
    0,
    optionalHeaderSize
  );

  assert.strictEqual(parsed.ddCount, dataDirectoryCount);
  assert.strictEqual(parsed.dataDirs.length, dataDirectoryCount);
  assert.deepStrictEqual(parsed.dataDirs[16], {
    index: 16,
    name: "",
    rva: 0x13572468,
    size: 0x24681357
  });
});
