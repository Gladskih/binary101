"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { subtractExplainedPeOverlay } from "../../../../analyzers/pe/payloads.js";
import { MockFile } from "../../../helpers/mock-file.js";
import { createCertificatePaddingFixture } from "../../../fixtures/pe-certificate-padding.js";
import { parseSecurityDirectory } from "../../../../analyzers/pe/security/index.js";

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
  const fixture = await createCertificatePaddingFixture();
  const result = await subtractExplainedPeOverlay(
    fixture.file,
    fixture.security,
    { ranges: [{ start: 100, end: 120, size: 20, findings: [] }] },
    null,
    rarPayloads
  );

  assert.equal(result, null);
});

void test("subtractExplainedPeOverlay keeps non-zero bytes before a certificate table", async () => {
  const fixture = await createCertificatePaddingFixture();
  fixture.bytes[119] = 1;
  const result = await subtractExplainedPeOverlay(
    new MockFile(fixture.bytes),
    fixture.security,
    { ranges: [{ start: 100, end: 120, size: 20, findings: [] }] },
    null,
    rarPayloads
  );

  assert.deepEqual(result, {
    ranges: [{ start: 118, end: 120, size: 2, findings: [] }]
  });
});

void test("subtractExplainedPeOverlay preserves zeros before an absent certificate table", async () => {
  const file = new MockFile(new Uint8Array(120));
  const security = await parseSecurityDirectory(file, [{ name: "SECURITY", rva: 120, size: 8 }]);
  const result = await subtractExplainedPeOverlay(file, security,
    { ranges: [{ start: 100, end: 120, size: 20, findings: [] }] }, null, rarPayloads);

  assert.deepEqual(result?.ranges, [{ start: 118, end: 120, size: 2, findings: [] }]);
});
