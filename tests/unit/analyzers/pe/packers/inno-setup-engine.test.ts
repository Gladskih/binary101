"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { extractInnoSetupEngine } from "../../../../../analyzers/pe/packers/inno-setup-engine.js";
import { createInnoFinding, createInnoSetupFixture } from "../../../../fixtures/inno-setup-fixture.js";

void test("extractInnoSetupEngine validates, decodes, and reverses the call filter", async () => {
  const fixture = createInnoSetupFixture();

  const bytes = await extractInnoSetupEngine(fixture.file, createInnoFinding());

  assert.deepEqual(bytes, fixture.decodedEngine);
});

void test("extractInnoSetupEngine rejects a changed block header", async () => {
  const fixture = createInnoSetupFixture();
  const finding = { ...createInnoFinding(), setupExeStoredSize: 1 };

  await assert.rejects(
    extractInnoSetupEngine(fixture.file, finding),
    /block header no longer matches/
  );
});

void test("extractInnoSetupEngine rejects oversized packed engines", async () => {
  const fixture = createInnoSetupFixture();
  const finding = { ...createInnoFinding(), setupExeStoredSize: 65 * 1024 * 1024 };

  await assert.rejects(extractInnoSetupEngine(fixture.file, finding), /exceeds the browser decode limit/);
});
