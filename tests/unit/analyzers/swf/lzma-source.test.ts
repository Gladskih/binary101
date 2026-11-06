import assert from "node:assert/strict";
import { test } from "node:test";
import { openZwsBody } from "../../../../analyzers/swf/lzma-source.js";
import { parseSwf } from "../../../../analyzers/swf/index.js";
import { createZws, createSwf } from "../../../fixtures/swf-fixtures.js";
import { MockFile } from "../../../helpers/mock-file.js";

void test("openZwsBody decodes an independent encoder stream with complete input and end marker", async () => {
  const file = new MockFile(createZws());
  const header = await parseSwf(file);
  assert.ok(header);

  const source = await openZwsBody(file, 0, file.size, header);

  assert.deepEqual(await source.readBytes(8, source.size - 8), createSwf().subarray(8));
  await source.finish();
  await source.close();
});

void test("openZwsBody rejects missing properties, truncated compressed data and appended bytes", async () => {
  const file = new MockFile(createZws());
  const header = await parseSwf(file);
  assert.ok(header);
  const missing = { signature: header.signature, version: header.version,
    fileLength: header.fileLength, issues: [] };

  await assert.rejects(openZwsBody(file, 0, file.size, missing), /properties are unavailable/);
  await assert.rejects(openZwsBody(file, 0, file.size - 6, header));
  const extended = new MockFile(Buffer.concat([file.data, Uint8Array.of(0)]));
  await assert.rejects(openZwsBody(extended, 0, extended.size, header), /complete input consumption/);
});
