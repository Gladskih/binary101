import assert from "node:assert/strict";
import { test } from "node:test";
import { createFileRangeReader } from "../../../../analyzers/file-range-reader.js";
import { readMipsOptions } from "../../../../analyzers/elf/mips-options.js";
import { readMips32RegInfo } from "../../../../analyzers/elf/mips-records.js";

const read = async (bytes: Uint8Array<ArrayBuffer>) => {
  const file = new File([bytes], "options");
  const issues: string[] = [];
  const options = await readMipsOptions(createFileRangeReader(file, 0, file.size),
    { offset: 0, size: file.size }, "little", readMips32RegInfo, issues);
  return { options, issues };
};

void test("reads bounded MIPS options including REGINFO payload", async () => {
  const bytes = new Uint8Array(32);
  bytes.set([1, 32, 2, 0, 3, 0, 0, 0]);
  bytes[8] = 4;
  assert.deepEqual(await read(bytes), { options: [{ kind: 1, section: 2, info: 3,
    registerInfo: { gprMask: 4, cprMasks: [0, 0, 0, 0], gpValue: 0n } }], issues: [] });
});

void test("rejects short headers, undersized options and records exceeding their container", async () => {
  assert.match((await read(new Uint8Array(7))).issues.join(" "), /size|truncated/);
  assert.match((await read(new Uint8Array(8))).issues.join(" "), /size/);
  assert.match((await read(new Uint8Array([1, 9, 0, 0, 0, 0, 0, 0]))).issues.join(" "), /size/);
});

void test("reports incomplete REGINFO and unknown option payloads", async () => {
  assert.match((await read(new Uint8Array([1, 8, 0, 0, 0, 0, 0, 0]))).issues.join(" "), /REGINFO/);
  const unknown = await read(new Uint8Array([9, 8, 0, 0, 0, 0, 0, 0]));
  assert.deepEqual(unknown.options, [{ kind: 9, section: 0, info: 0 }]);
  assert.match(unknown.issues.join(" "), /kind 9/);
});

const oversizedOptions = (): Uint8Array<ArrayBuffer> => {
  const bytes = new Uint8Array(800008);
  for (let offset = 0; offset < bytes.length; offset += 8) bytes[offset + 1] = 8;
  return bytes;
};

void test("limits retained options", async () => {
  assert.match((await read(oversizedOptions())).issues.at(-1)!, /limit/);
});
