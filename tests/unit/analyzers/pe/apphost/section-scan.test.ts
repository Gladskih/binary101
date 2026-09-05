import assert from "node:assert/strict";
import { test } from "node:test";
import { scanAppHostSection } from "../../../../../analyzers/pe/apphost/section-scan.js";
import { createPeAppHostFixture } from "../../../../fixtures/pe-apphost-fixture.js";

const chunkedBlob = (bytes: Uint8Array, chunkSize: number): Blob => ({
  size: bytes.length,
  slice: (start: number, end: number) => ({
    stream: () => new ReadableStream<Uint8Array>({
      start(controller) {
        for (let offset = start; offset < end; offset += chunkSize) {
          controller.enqueue(bytes.slice(offset, Math.min(offset + chunkSize, end)));
        }
        controller.close();
      }
    })
  })
} as Blob);

const observedBlob = (bytes: Uint8Array) => {
  const ranges: number[][] = [];
  const streams: ReadableStream<Uint8Array>[] = [];
  let cancellations = 0;
  return {
    file: { size: bytes.length, slice: (start: number, end: number) => {
      ranges.push([start, end]);
      const stream = new ReadableStream<Uint8Array>({
        start(controller) { controller.enqueue(bytes.slice(start, end)); },
        // Deliberately leave the source open: the scanner must cancel it after
        // consuming the bounded range, then release the reader's lock.
        cancel() { cancellations += 1; }
      });
      streams.push(stream);
      return { stream: () => stream };
    } } as Blob,
    ranges,
    streams,
    cancellations: () => cancellations
  };
};

void test("apphost scan preserves markers crossing chunk boundaries without duplicates", async () => {
  const fixture = createPeAppHostFixture();

  const result = await scanAppHostSection(chunkedBlob(fixture.bytes, 7), 0, fixture.bytes.length);

  assert.deepEqual(result.locators, [0x150]);
  assert.deepEqual(result.bindings, [{ offset: 0x287, kind: "managed-assembly" }]);
  assert.deepEqual(result.issues, []);
});

void test("apphost scan finds a placeholder across chunks", async () => {
  // SDK's SHA-256("foobar") placeholder, apphost/apphost.c.
  const fixture = createPeAppHostFixture(0n,
    "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2");

  const result = await scanAppHostSection(chunkedBlob(fixture.bytes, 13), 0, fixture.bytes.length);

  assert.deepEqual(result.bindings, [{ offset: 0x280, kind: "unbound-placeholder" }]);
});

void test("apphost scan retains locators after the binding budget is exhausted", async () => {
  const fixture = createPeAppHostFixture();
  const bindings = new TextEncoder().encode("noise.dll\0".repeat(100));
  const bytes = new Uint8Array(bindings.length + fixture.bytes.length);
  bytes.set(bindings);
  bytes.set(fixture.bytes, bindings.length);

  const result = await scanAppHostSection(new Blob([bytes]), 0, bytes.length);

  assert.deepEqual(result.locators, [bindings.length + 0x150]);
  // The scanner's documented resource budget is 64 candidates per category.
  assert.equal(result.bindings.length, 64);
  assert.equal(result.issues.length, 1);
  assert.match(result.issues.join(""), /limit.*incomplete/);
});

void test("apphost scan bounds malformed ranges", async () => {
  const file = new Blob(["data"]);

  assert.deepEqual(await scanAppHostSection(file, -1, 1),
    { locators: [], bindings: [], issues: [] });
  assert.deepEqual((await scanAppHostSection(file, 0, Number.NaN)).locators, []);
  assert.deepEqual((await scanAppHostSection(file, file.size, 1)).locators, []);
  assert.deepEqual((await scanAppHostSection(file, 0, 0)).locators, []);
  assert.deepEqual((await scanAppHostSection(file, 0, file.size * 2)).issues, []);
});

void test("apphost scan reports a stream ending before the requested range", async () => {
  const file = chunkedBlob(new Uint8Array(0), 1);
  Object.defineProperty(file, "size", { value: 1 });

  const result = await scanAppHostSection(file, 0, 1);

  assert.match(result.issues.join(""), /truncated/);
});

void test("apphost scan includes a suffix ending at EOF and clamps nonzero ranges", async () => {
  const source = observedBlob(new TextEncoder().encode("pad.dll\0"));

  const result = await scanAppHostSection(source.file, "pad".length, source.file.size);

  assert.deepEqual(source.ranges, [["pad".length, source.file.size]]);
  assert.deepEqual(result.bindings, [{ offset: "pad".length, kind: "managed-assembly" }]);
  assert.equal(source.cancellations(), 1);
  assert.equal(source.streams[0]?.locked, false);
});

for (const [offset, size] of [
  [4, 1], [5, 1], [0, 0], [0, -1], [0, 0.5], [0.5, 1], [Number.NaN, 1], [0, Infinity]
] as const) {
  void test(`apphost scan avoids all I/O for invalid range ${offset} + ${size}`, async () => {
    // The four-byte source makes offsets 4 and 5 exact EOF and beyond EOF.
    const source = observedBlob(new TextEncoder().encode("data"));

    const result = await scanAppHostSection(source.file, offset, size);

    assert.deepEqual(source.ranges, []);
    assert.deepEqual(result, { locators: [], bindings: [], issues: [] });
  });
}

void test("apphost scan does not repeat a suffix ending exactly at a chunk boundary", async () => {
  const bytes = new TextEncoder().encode("A.dll\0B.dll\0");

  const result = await scanAppHostSection(chunkedBlob(bytes, "A.dll\0".length), 0, bytes.length);

  assert.deepEqual(result.bindings, [
    { offset: 1, kind: "managed-assembly" },
    { offset: "A.dll\0B".length, kind: "managed-assembly" }
  ]);
});

void test("apphost scan keeps allocations bounded independently of section length", async context => {
  const sizes: number[] = [];
  const originalSet = Uint8Array.prototype.set;
  const chunkSize = 128;
  const bytes = new Uint8Array(chunkSize * 20);
  context.mock.method(Uint8Array.prototype, "set", function (
    this: Uint8Array, source: ArrayLike<number>, offset?: number
  ): void {
    sizes.push(this.byteLength);
    originalSet.call(this, source, offset);
  });

  await scanAppHostSection(chunkedBlob(bytes, chunkSize), 0, bytes.length);

  // The longest pattern is the SDK's 64-character hex SHA-256 placeholder;
  // retaining 63 tail bytes suffices, regardless of total section length.
  assert.equal(sizes.length, 40); // two copies per each of the twenty chunks
  assert.equal(Math.max(...sizes), chunkSize + 63);
});
