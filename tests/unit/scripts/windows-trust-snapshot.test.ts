import assert from "node:assert/strict";
import { mkdtempDisposableSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test, type TestContext } from "node:test";
import { ensureWindowsTrustSnapshot } from "../../../scripts/windows-trust-snapshot.js";
import { createWindowsTrustSnapshot as createSnapshot } from "../../fixtures/windows-trust-snapshot.js";

const createSnapshotPath = (context: TestContext): string => {
  const directory = mkdtempDisposableSync(join(tmpdir(), "binary101-trust-"));
  context.after(() => directory.remove());
  return join(directory.path, "snapshot.json");
};

for (const platform of ["win32", "linux", "darwin"]) {
  void test(`reuses a populated snapshot on ${platform} without exporting again`, async context => {
    const path = createSnapshotPath(context);
    writeFileSync(path, JSON.stringify(createSnapshot()));

    await ensureWindowsTrustSnapshot(path, platform, async () => assert.fail("Unexpected export"));
  });
}

void test("creates a missing snapshot on Windows", async context => {
  const path = createSnapshotPath(context);
  const generateSnapshot = context.mock.fn(async () => {
    writeFileSync(path, JSON.stringify(createSnapshot()));
  });
  const warning = context.mock.method(console, "warn", () => {});

  await ensureWindowsTrustSnapshot(path, "win32", generateSnapshot);

  assert.equal(generateSnapshot.mock.callCount(), 1);
  assert.match(String(warning.mock.calls[0]?.arguments[0]),
    /Preparing Windows Authenticode trust snapshot:.*ENOENT/);
});

void test("explains how to supply a missing snapshot outside Windows", async context => {
  const path = createSnapshotPath(context);
  const generateSnapshot = context.mock.fn(async () => assert.fail("Unexpected export"));

  await assert.rejects(ensureWindowsTrustSnapshot(path, "linux", generateSnapshot), error => {
    assert.ok(error instanceof Error);
    assert.match(error.message, /Generate the snapshot on Windows.*windows-authenticode-trust CI artifact/);
    assert.ok(error.message.includes(`scripts/dump-windows-authenticode-trust.ps1 -OutputPath "${path}"`));
    return true;
  });

  assert.equal(generateSnapshot.mock.callCount(), 0);
});

const malformedSnapshots: [string, unknown, RegExp][] = [
  ["null input", null, /no valid generation date/],
  ["wrong schema", { ...createSnapshot(), schemaVersion: 2 }, /schemaVersion is not 1/],
  ["placeholder", { ...createSnapshot(), generatedAt: "", trustedCAs: [] }, /no valid generation date/],
  ["invalid generation date", { ...createSnapshot(), generatedAt: "invalid" }, /no valid generation date/],
  ["empty source", { ...createSnapshot(), source: "" }, /has no source/],
  ["missing source", { ...createSnapshot(), source: undefined }, /has no source/],
  ["whitespace source", { ...createSnapshot(), source: " " }, /has no source/],
  ["missing generation date", { ...createSnapshot(), generatedAt: undefined }, /no valid generation date/],
  ["empty trusted roots", { ...createSnapshot(), trustedCAs: [] }, /trusted root list is empty/],
  ["missing trusted list", { ...createSnapshot(), trustedCAs: undefined }, /trusted root list is empty/],
  ["missing disallowed list", { ...createSnapshot(), revokedCAs: undefined }, /revokedCAs is not an array/],
  ["invalid disallowed list", { ...createSnapshot(), revokedCAs: "invalid" }, /revokedCAs is not an array/],
  ["certificate without DER", { ...createSnapshot(), trustedCAs: [{ thumbprint: "ABCD" }] },
    /without DER data/],
  ["revoked certificate without DER", { ...createSnapshot(), revokedCAs: [{ thumbprint: "ABCD" }] },
    /without DER data/],
  ["incomplete store export", { ...createSnapshot(), warnings: ["Disallowed could not be read."] },
    /Disallowed could not be read/],
  ["multiple store errors", { ...createSnapshot(),
    warnings: ["Root could not be read.", "Disallowed could not be read."] },
    /Disallowed could not be read\.; Root could not be read/]
];

for (const [label, snapshot, expectedProblem] of malformedSnapshots) {
  void test(`rejects ${label} outside Windows`, async context => {
    const path = createSnapshotPath(context);
    writeFileSync(path, JSON.stringify(snapshot));

    await assert.rejects(ensureWindowsTrustSnapshot(path, "linux",
      async () => assert.fail("Unexpected export")), expectedProblem);
  });
}

void test("replaces a placeholder on Windows", async context => {
  const path = createSnapshotPath(context);
  writeFileSync(path, JSON.stringify({ ...createSnapshot(), generatedAt: "", trustedCAs: [] }));
  const generateSnapshot = context.mock.fn(async () => {
    writeFileSync(path, JSON.stringify(createSnapshot()));
  });

  await ensureWindowsTrustSnapshot(path, "win32", generateSnapshot);

  assert.equal(generateSnapshot.mock.callCount(), 1);
});

void test("replaces truncated JSON on Windows", async context => {
  const path = createSnapshotPath(context);
  writeFileSync(path, "{");
  const generateSnapshot = context.mock.fn(async () => {
    writeFileSync(path, JSON.stringify(createSnapshot()));
  });

  await ensureWindowsTrustSnapshot(path, "win32", generateSnapshot);

  assert.equal(generateSnapshot.mock.callCount(), 1);
});

void test("propagates certificate export failures", async context => {
  const path = createSnapshotPath(context);
  const failure = new Error("Certificate store access denied");

  await assert.rejects(ensureWindowsTrustSnapshot(path, "win32", async () => { throw failure; }), failure);
});

void test("rejects an export that did not produce a snapshot", async context => {
  await assert.rejects(ensureWindowsTrustSnapshot(createSnapshotPath(context), "win32", async () => {}),
    /Generated Windows trust snapshot is invalid/);
});

void test("rejects a newly exported empty snapshot", async context => {
  const path = createSnapshotPath(context);

  await assert.rejects(ensureWindowsTrustSnapshot(path, "win32", async () => {
    writeFileSync(path, JSON.stringify({ ...createSnapshot(), trustedCAs: [] }));
  }), /Generated Windows trust snapshot is invalid: The Windows trusted root list is empty/);
});
