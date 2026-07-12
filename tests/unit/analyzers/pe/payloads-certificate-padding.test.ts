"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { subtractExplainedPeOverlay } from "../../../../analyzers/pe/payloads.js";
import { MockFile } from "../../../helpers/mock-file.js";

const rarPayloads = {
  entries: [{
    start: 100,
    end: 118,
    format: "rar" as const,
    provenance: {
      location: "overlay" as const,
      discovery: "archive-scan" as const,
      association: "unattributed" as const,
      validation: "rar-end-archive" as const
    }
  }]
};

void test("subtractExplainedPeOverlay excludes certificate padding after a validated archive", async () => {
  const result = await subtractExplainedPeOverlay(
    new MockFile(new Uint8Array(120), "signed-installer.exe"),
    120,
    { ranges: [{ start: 100, end: 120, size: 20, findings: [] }] },
    null,
    rarPayloads
  );

  assert.equal(result, null);
});

void test("subtractExplainedPeOverlay keeps non-zero bytes before a certificate table", async () => {
  const bytes = new Uint8Array(120);
  bytes[119] = 1;
  const result = await subtractExplainedPeOverlay(
    new MockFile(bytes, "signed-installer.exe"),
    120,
    { ranges: [{ start: 100, end: 120, size: 20, findings: [] }] },
    null,
    rarPayloads
  );

  assert.deepEqual(result, {
    ranges: [{ start: 118, end: 120, size: 2, findings: [] }]
  });
});
