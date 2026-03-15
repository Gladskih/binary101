"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseSecurityDirectory } from "../../analyzers/pe/security.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";

type CoverageEntry = { label: string; start: number; size: number };

const collectCoverage = (): {
  regions: CoverageEntry[];
  add: (label: string, start: number, size: number) => void;
} => {
  const regions: CoverageEntry[] = [];
  const add = (label: string, start: number, size: number) => {
    regions.push({ label, start, size });
  };
  return { regions, add };
};

void test("parseSecurityDirectory walks WIN_CERTIFICATE entries", async () => {
  const bytes = new Uint8Array(0x200).fill(0);
  const secOff = 0x100;
  const dv = new DataView(bytes.buffer);
  dv.setUint32(secOff + 0, 12, true);
  dv.setUint16(secOff + 4, 0x0200, true);
  dv.setUint16(secOff + 6, 0x0002, true);
  const second = secOff + 16;
  dv.setUint32(second + 0, 16, true);
  dv.setUint16(second + 4, 0x0200, true);
  dv.setUint16(second + 6, 0x0002, true);

  const dirs = [{ name: "SECURITY", rva: secOff, size: 40 }];
  const { regions, add } = collectCoverage();
  const parsed = await parseSecurityDirectory(new MockFile(bytes, "sec.bin"), dirs, add);
  const sec = expectDefined(parsed);
  const firstCert = expectDefined(sec.certs[0]);

  assert.strictEqual(sec.count, 2);
  assert.strictEqual(sec.certs.length, 2);
  assert.strictEqual(firstCert.certificateType, 0x0002);
  assert.strictEqual(firstCert.typeName.includes("PKCS#7"), true);
  assert.ok(firstCert.authenticode);
  assert.ok(regions.some(r => r.label.includes("SECURITY")));
});

void test("parseSecurityDirectory walks all certificates in the declared table", async () => {
  const certCount = 9;
  const secOff = 0x40;
  const bytes = new Uint8Array(secOff + certCount * 8).fill(0);
  const dv = new DataView(bytes.buffer);
  for (let index = 0; index < certCount; index += 1) {
    const off = secOff + index * 8;
    dv.setUint32(off + 0, 8, true);
    dv.setUint16(off + 4, 0x0200, true);
    dv.setUint16(off + 6, 0x0001, true);
  }

  const parsed = await parseSecurityDirectory(
    new MockFile(bytes, "sec-many.bin"),
    [{ name: "SECURITY", rva: secOff, size: certCount * 8 }],
    () => {}
  );

  const sec = expectDefined(parsed);
  assert.strictEqual(sec.count, certCount);
  assert.strictEqual(sec.certs.length, certCount);
});

void test("parseSecurityDirectory reports corruption when rounded certificate sizes do not cover the table", async () => {
  const secOff = 0x80;
  const bytes = new Uint8Array(0x200).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(secOff + 0, 12, true);
  dv.setUint16(secOff + 4, 0x0200, true);
  dv.setUint16(secOff + 6, 0x0002, true);

  const parsed = await parseSecurityDirectory(
    new MockFile(bytes, "sec-gap.bin"),
    [{ name: "SECURITY", rva: secOff, size: 40 }],
    () => {}
  );

  const sec = expectDefined(parsed);
  assert.strictEqual(sec.count, 1);
  assert.ok(sec.warnings?.some(warning => warning.toLowerCase().includes("corrupt")));
});

void test("parseSecurityDirectory preserves truncated directories as warnings instead of dropping them", async () => {
  const secOff = 0x40;
  const bytes = new Uint8Array(secOff + 4).fill(0);

  const parsed = await parseSecurityDirectory(
    new MockFile(bytes, "sec-truncated.bin"),
    [{ name: "SECURITY", rva: secOff, size: 8 }],
    () => {}
  );

  const sec = expectDefined(parsed);
  assert.strictEqual(sec.count, 0);
  assert.ok(sec.warnings?.some(warning => warning.toLowerCase().includes("truncated")));
});
