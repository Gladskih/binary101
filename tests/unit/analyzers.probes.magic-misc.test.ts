"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { miscProbes } from "../../analyzers/probes/magic-misc.js";

const dvFrom = (bytes: ArrayLike<number>): DataView => new DataView(new Uint8Array(bytes).buffer);
const run = (bytes: ArrayLike<number>): string | null => miscProbes.map(p => p(dvFrom(bytes))).find(Boolean) || null;

void test("detects documents, compound files and executables", () => {
  assert.strictEqual(run([0x25, 0x50, 0x44, 0x46, 0x2d]), "PDF document");
  const cfb = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
  assert.strictEqual(run(cfb), "Microsoft Compound File (e.g. Office 97-2003, MSI)");
  const lnk = new Uint8Array(0x14);
  const dv = new DataView(lnk.buffer);
  dv.setUint32(0, 0x4c, true);
  dv.setUint32(4, 0x00021401, true);
  dv.setUint8(12, 0xc0);
  dv.setUint8(19, 0x46);
  assert.strictEqual(run(lnk), "Windows shortcut (.lnk)");
  assert.strictEqual(run([0x00, 0x61, 0x73, 0x6d]), "WebAssembly binary (WASM)");
});

void test("detects pdb, dex, djvu and help file signatures", () => {
  const pdbHeader = "Microsoft C/C++ MSF 7.00 Program Database";
  const pdb = new Uint8Array(pdbHeader.length + 1);
  pdb.set([...pdbHeader].map(ch => ch.charCodeAt(0)));
  assert.strictEqual(run(pdb), "Microsoft PDB debug symbols");
  const dex = [..."dex\n035\0"].map(ch => ch.charCodeAt(0));
  assert.strictEqual(run(dex), "Android DEX bytecode");
  const djvu = [..."AT&TFORM"].map(c => c.charCodeAt(0)).concat([0, 0, 0, 0], ..."DJVU".split("").map(c => c.charCodeAt(0)));
  assert.strictEqual(run(djvu), "DjVu document");
  assert.strictEqual(run([0x3f, 0x5f, 0x03, 0x00]), "Windows Help file (HLP)");
});

void test("returns null for unknown bytes", () => {
  assert.strictEqual(run([0x01, 0x02, 0x03, 0x04]), null);
});
