import assert from "node:assert/strict";
import { test } from "node:test";
import { parseGoBuildInfo } from "../../../../analyzers/elf/go-build-info.js";
import { relocationSection } from "../../../fixtures/elf-relocations.js";
import { MockFile } from "../../../helpers/mock-file.js";

const fixture = () => {
  // Go 1.18+ buildinfo: 32-byte header, inline flag, varint-prefixed strings.
  // https://go.dev/src/debug/buildinfo/buildinfo.go
  const version = new TextEncoder().encode("go1.26.0");
  const module = new TextEncoder().encode("path\texample.test/hello\n");
  const bytes = new Uint8Array(32 + 1 + version.length + 1 + 32 + module.length);
  bytes[0] = 255;
  bytes.set(new TextEncoder().encode(" Go buildinf:"), 1);
  bytes[14] = 8;
  bytes[15] = 2;
  bytes[32] = version.length;
  bytes.set(version, 33);
  bytes[33 + version.length] = module.length + 32;
  bytes.set(module, 34 + version.length + 16);
  return bytes;
};

const parse = (bytes: Uint8Array, issues: string[]) => parseGoBuildInfo(
  new MockFile(bytes), [relocationSection(1, { name: ".go.buildinfo", size: BigInt(bytes.length) })], issues);

void test("reads inline Go toolchain and module information", async () => {
  const issues: string[] = [];
  assert.deepEqual(await parse(fixture(), issues), {
    version: "go1.26.0", moduleInfo: "path\texample.test/hello\n"
  });
  assert.deepEqual(issues, []);
});

void test("warns on missing headers, legacy layout and truncated strings", async () => {
  const issues: string[] = [];
  assert.equal(await parse(new Uint8Array(), issues), null);
  const legacy = fixture();
  legacy[15] = 0;
  assert.equal(await parse(legacy, issues), null);
  assert.equal(await parse(fixture().subarray(0, 34), issues), null);
  assert.equal(issues.length, 3);
  assert.match(issues[0]!, /header is invalid or truncated/);
  assert.match(issues[1]!, /pre-1.18 pointer layout/);
  assert.match(issues[2]!, /strings are invalid or truncated/);
  assert.equal(await parseGoBuildInfo(new MockFile(new Uint8Array()), [], []), null);
});

void test("checks the metadata resource limit independently of the file bounds", async () => {
  const bytes = new Uint8Array(1024 * 1024 + 1);
  bytes.set(fixture());
  const issues: string[] = [];
  assert.ok(await parse(bytes.subarray(0, -1), issues));
  assert.deepEqual(issues, []);
  assert.equal(await parse(bytes, issues), null);
  assert.match(issues.join(" "), /exceeds the 1 MiB limit/);
});

void test("handles a length prefix truncated at EOF without throwing", async () => {
  const bytes = fixture().slice(0, 33);
  bytes[32] = 128;
  const issues: string[] = [];
  assert.equal(await parse(bytes, issues), null);
  assert.match(issues.join(" "), /strings are invalid or truncated/);
});

void test("does not decode unframed module bytes as valid metadata", async () => {
  const bytes = fixture();
  bytes[bytes.length - 17] = 0;
  assert.deepEqual(await parse(bytes, []), { version: "go1.26.0", moduleInfo: "" });
});

for (const [offset, value] of [[0, 0], [1, 0], [15, 0], [32, 0], [32, 127]]) {
  void test(`rejects invalid Go build info at ${offset}: ${value}`, async () => {
    const bytes = fixture();
    bytes[offset!] = value!;
    const issues: string[] = [];
    assert.equal(await parse(bytes, issues), null);
    assert.equal(issues.length, 1);
  });
}

void test("rejects unterminated and overflowing string lengths", async () => {
  const bytes = fixture();
  bytes.fill(255, 32, 42);
  const issues: string[] = [];
  assert.equal(await parse(bytes, issues), null);
  bytes[41] = 1;
  assert.equal(await parse(bytes, issues), null);
  assert.equal(issues.length, 2);
});

void test("accepts multi-byte lengths and empty module metadata", async () => {
  const bytes = new Uint8Array(32 + 2 + 128 + 1);
  bytes.set(fixture().subarray(0, 32));
  bytes.set([128, 1], 32);
  bytes.fill(65, 34, bytes.length - 1);
  const issues: string[] = [];
  assert.deepEqual(await parse(bytes, issues), { version: "A".repeat(128), moduleInfo: "" });
  assert.deepEqual(issues, []);
});

void test("rejects invalid UTF-8 instead of displaying replacement characters", async () => {
  const bytes = fixture();
  bytes[33] = 255;
  const issues: string[] = [];
  assert.equal(await parse(bytes, issues), null);
  assert.match(issues.join(" "), /UTF-8/);
});

for (const [offset, size] of [[-1n, 1n], [1n, 1000n], [0n, 1048577n]]) {
  void test(`bounds-checks Go build info ${offset}:${size}`, async () => {
    const issues: string[] = [];
    assert.equal(await parseGoBuildInfo(new MockFile(fixture()), [relocationSection(1,
      { name: ".go.buildinfo", offset: offset!, size: size! })], issues), null);
    assert.equal(issues.length, 1);
  });
}
