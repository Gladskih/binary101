import assert from "node:assert/strict";
import { createElfMetadataFile } from "./elf-metadata-file.js";

export const createElfItaniumFile = (): Uint8Array<ArrayBuffer> => {
  const fixture = createElfMetadataFile();
  const bytes = Buffer.from(fixture.file.data);
  const position = bytes.indexOf(fixture.expected.exportSymbol + "\0");
  assert.ok(position >= 0);
  assert.ok("_Z1fi".length <= fixture.expected.exportSymbol.length);
  bytes.fill(0, position, position + fixture.expected.exportSymbol.length);
  bytes.set(new TextEncoder().encode("_Z1fi"), position);
  return bytes;
};
