"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createResourceSpanResolver } from "../../../../../analyzers/pe/resources/relative-offsets.js";

const createResolver = (
  size = 0x20,
  base = 0,
  fileSize = base + size,
  rvaToOff: (rva: number) => number | null = rva => rva - 0x1000
) => createResourceSpanResolver(
  { name: "RESOURCE", rva: 0x1000, size },
  base,
  fileSize,
  rvaToOff
);

void test("resource span resolver exposes direct RVA mapping and mapped EOF diagnostics", () => {
  const resolver = createResourceSpanResolver(
    { name: "RESOURCE", rva: 0x1000, size: 0x20 },
    0,
    10,
    rva => (rva === 0x1004 ? 6 : rva - 0x1000)
  );

  assert.equal(resolver.resolveRvaOffset(0x1004), 6);
  assert.equal(resolver.formatRelOffset(0xffffffff), "0xffffffff");
  assert.equal(
    resolver.describeRelOffsetFailure(4, 8, "Resource directory"),
    "Resource directory is truncated by end of file."
  );
});

void test("resource span resolver rejects offsets outside the declared resource span", () => {
  const resolver = createResolver();

  assert.equal(resolver.resolveRelOffset(-1, 1), null);
  assert.equal(resolver.resolveRelOffset(0, -1), null);
  assert.equal(resolver.resolveRelOffset(0, 0), 0);
  assert.equal(resolver.resolveRelOffset(0x1f, 2), null);
  assert.equal(
    resolver.describeRelOffsetFailure(-1, 1, "Resource directory"),
    "Resource directory lies outside the declared span."
  );
  assert.equal(
    resolver.describeRelOffsetFailure(0, -1, "Resource directory"),
    "Resource directory lies outside the declared span."
  );
  assert.equal(
    resolver.describeRelOffsetFailure(0, 0, "Resource directory"),
    "Resource directory could not be mapped within the declared resource span."
  );
  assert.equal(
    resolver.describeRelOffsetFailure(0x1f, 2, "Resource directory"),
    "Resource directory lies outside the declared span."
  );
});

void test(
  "resource span resolver falls back only when the mapped RVA aliases the resource base",
  () => {
  const resolver = createResolver(0x20, 0x100, 0x200, rva => {
    if (rva === 0x1000) return 0x100;
    if (rva === 0x1004) return 0x100;
    if (rva === 0x1008) return -1;
    return null;
  });

  assert.equal(resolver.resolveRelOffset(0, 4), 0x100);
  assert.equal(resolver.resolveRelOffset(4, 4), 0x104);
  assert.equal(resolver.resolveRelOffset(8, 4), 0x108);
  }
);

void test("resource span resolver accepts mapped zero offsets and exact EOF boundaries", () => {
  const zeroMapped = createResolver(0x20, 0x100, 0x200, rva => rva === 0x1004 ? 0 : null);
  const eofMapped = createResolver(0x20, 0x100, 0x200, rva => rva === 0x1008 ? 0x1fc : null);

  assert.equal(zeroMapped.resolveRelOffset(4, 4), 0);
  assert.equal(eofMapped.resolveRelOffset(8, 4), 0x1fc);
});

void test("resource span resolver rejects mapped ranges that extend past EOF", () => {
  const resolver = createResolver(0x20, 0x100, 10, rva => rva === 0x1004 ? 6 : null);

  assert.equal(resolver.resolveRelOffset(4, 8), null);
});

void test("resource span resolver distinguishes mapped offsets from fallback aliases", () => {
  const resolver = createResolver(0x20, 0x100, 0x200, rva => {
    if (rva === 0x1004) return 0x120;
    if (rva === 0x1008) return 0x100;
    return null;
  });

  assert.equal(resolver.resolveRelOffset(4, 4), 0x120);
  assert.equal(resolver.resolveRelOffset(8, 4), 0x108);
});

void test(
  "resource span resolver prefers mapped EOF diagnostics over valid fallback offsets",
  () => {
  const resolver = createResolver(0x20, 0, 0x100, rva => rva === 0x1004 ? 0xfc : null);

  assert.equal(
    resolver.describeRelOffsetFailure(4, 8, "Resource directory"),
    "Resource directory is truncated by end of file."
  );
  }
);

void test("resource span resolver handles mapped EOF diagnostic boundaries", () => {
  const mappedAtZero = createResolver(0x20, 0x100, 10, rva => rva === 0x1004 ? 0 : null);
  const mappedAtEof = createResolver(0x20, 0x100, 10, rva => rva === 0x1004 ? 10 : null);
  const mappedExactEnd = createResolver(0x20, 0x100, 10, rva => rva === 0x1004 ? 6 : null);
  const mappedNegative = createResolver(0x20, 0x100, 10, rva => rva === 0x1004 ? -1 : null);

  assert.equal(
    mappedAtZero.describeRelOffsetFailure(4, 11, "Resource data"),
    "Resource data is truncated by end of file."
  );
  assert.equal(
    mappedAtEof.describeRelOffsetFailure(4, 1, "Resource data"),
    "Resource data could not be mapped within the declared resource span."
  );
  assert.equal(
    mappedExactEnd.describeRelOffsetFailure(4, 4, "Resource data"),
    "Resource data could not be mapped within the declared resource span."
  );
  assert.equal(
    mappedNegative.describeRelOffsetFailure(4, 12, "Resource data"),
    "Resource data could not be mapped within the declared resource span."
  );
});

void test("resource span resolver handles fallback EOF diagnostic boundaries", () => {
  const fallbackAtEof = createResolver(0x20, 10, 10, () => null);
  const fallbackExactEnd = createResolver(0x20, 6, 10, () => null);
  const fallbackTruncated = createResolver(0x20, 6, 10, () => null);

  assert.equal(
    fallbackAtEof.describeRelOffsetFailure(0, 1, "Resource data"),
    "Resource data could not be mapped within the declared resource span."
  );
  assert.equal(
    fallbackExactEnd.describeRelOffsetFailure(0, 4, "Resource data"),
    "Resource data could not be mapped within the declared resource span."
  );
  assert.equal(
    fallbackTruncated.describeRelOffsetFailure(0, 5, "Resource data"),
    "Resource data is truncated by end of file."
  );
});

void test(
  "resource span resolver rejects ranges that exceed the span even when fallback could fit",
  () => {
  const resolver = createResolver(0x20, 0, 0x100, () => null);

  assert.equal(resolver.resolveRelOffset(0x1f, 2), null);
  }
);

void test("resource span resolver reports fallback EOF truncation and unmappable spans", () => {
  const truncated = createResolver(0x20, 0x100, 0x110, () => null);
  const unmapped = createResolver(0x20, 0x120, 0x110, () => null);

  assert.equal(truncated.resolveRelOffset(0x0c, 8), null);
  assert.equal(
    truncated.describeRelOffsetFailure(0x0c, 8, "Resource string"),
    "Resource string is truncated by end of file."
  );
  assert.equal(unmapped.resolveRelOffset(0, 4), null);
  assert.equal(
    unmapped.describeRelOffsetFailure(0, 4, "Resource string"),
    "Resource string could not be mapped within the declared resource span."
  );
});
