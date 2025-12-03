"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { MockFile } from "../helpers/mock-file.js";
import { probeMzFormat } from "../../analyzers/mz-probe.js";

const makeFile = (bytes: Uint8Array): File => new MockFile(bytes, "sample.bin", "application/octet-stream");

void test("probeMzFormat returns mz when e_lfanew is zero or past file end", async () => {
  const buf = new Uint8Array(64).fill(0);
  buf[0] = 0x4d; buf[1] = 0x5a;
  const file = makeFile(buf);
  const dv = new DataView(buf.buffer);
  const result = await probeMzFormat(file, dv);
  assert.deepEqual(result, { kind: "mz", eLfanew: 0 });
});

void test("probeMzFormat detects PE, NE and LX signatures", async () => {
  const makeKind = async (sig: string): Promise<string | null> => {
    const buf = new Uint8Array(256).fill(0);
    buf[0] = 0x4d; buf[1] = 0x5a;
    const view = new DataView(buf.buffer);
    view.setUint32(0x3c, 0x80, true);
    [...sig].forEach((ch, idx) => view.setUint8(0x80 + idx, ch.charCodeAt(0)));
    const res = await probeMzFormat(makeFile(buf), view);
    return res?.kind ?? null;
  };

  assert.strictEqual(await makeKind("PE\u0000\u0000"), "pe");
  assert.strictEqual(await makeKind("NE00"), "ne");
  assert.strictEqual(await makeKind("LX00"), "lx");
});
