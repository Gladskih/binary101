"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { detectInnoSetup } from "../../../../../analyzers/pe/packers/inno-setup.js";
import {
  createInnoFinding,
  createInnoSetupFixture,
  INNO_TABLE_OFFSET
} from "../../../../fixtures/inno-setup-fixture.js";
import { MockFile } from "../../../../helpers/mock-file.js";

void test("detectInnoSetup confirms a CRC-valid loader table and decoded PE engine", async () => {
  const fixture = createInnoSetupFixture();

  const result = await detectInnoSetup({ reader: fixture.file, resources: fixture.resources });

  assert.deepEqual(result.warnings, []);
  assert.deepEqual(result.findings[0], {
    ...createInnoFinding(),
    evidence: [
      "The RCDATA 11111 loader offset table has a recognized ID and matching CRC-32.",
      "All declared Inno Setup data, header, engine, and total-size bounds are ordered and in-file.",
      "The embedded setup engine decoded as LZMA, passed chunk and output CRC-32 checks, and is PE."
    ]
  });
});

void test("detectInnoSetup ignores files without the offset-table resource", async () => {
  const fixture = createInnoSetupFixture();

  const result = await detectInnoSetup({ reader: fixture.file });

  assert.deepEqual(result, { findings: [], warnings: [] });
});

void test("detectInnoSetup rejects an unexpected offset-table resource size", async () => {
  const fixture = createInnoSetupFixture();
  fixture.resources.paths![0] = { ...fixture.resources.paths![0]!, size: 43 };

  const result = await detectInnoSetup({ reader: fixture.file, resources: fixture.resources });

  assert.deepEqual(result.findings, []);
  assert.deepEqual(result.warnings, [
    "Inno Setup loader offset table resource has an unsupported size."
  ]);
});

void test("detectInnoSetup rejects a loader-table CRC mismatch", async () => {
  const fixture = createInnoSetupFixture();
  const bytes = fixture.file.data.slice();
  bytes[INNO_TABLE_OFFSET + 40] = (bytes[INNO_TABLE_OFFSET + 40] ?? 0) ^ 0xff;

  const result = await detectInnoSetup({ reader: new MockFile(bytes), resources: fixture.resources });

  assert.deepEqual(result.findings, []);
  assert.deepEqual(result.warnings, ["Inno Setup loader offset table CRC-32 does not match."]);
});

void test("detectInnoSetup rejects a compressed-chunk CRC mismatch", async () => {
  const fixture = createInnoSetupFixture();
  const bytes = fixture.file.data.slice();
  const crcOffset = createInnoFinding().setupExeOffset + 9;
  bytes[crcOffset] = (bytes[crcOffset] ?? 0) ^ 0xff;

  const result = await detectInnoSetup({ reader: new MockFile(bytes), resources: fixture.resources });

  assert.deepEqual(result.findings, []);
  assert.deepEqual(result.warnings, ["Inno Setup compressed chunk CRC-32 does not match."]);
});
