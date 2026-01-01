"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderRichHeader } from "../../renderers/pe/rich-header.js";
import type { PeParseResult } from "../../analyzers/pe/index.js";

void test("renderRichHeader returns empty output when Rich header is absent", () => {
  const pe = { dos: { stub: { kind: "none", note: "" } } } as unknown as PeParseResult;
  const out: string[] = [];
  renderRichHeader(pe, out);
  assert.strictEqual(out.join(""), "");
});

void test("renderRichHeader renders a summary and annotated entry table", () => {
  const pe = {
    dos: {
      stub: { kind: "none", note: "" },
      rich: {
        xorKey: 0x12345678,
        checksum: 0x0,
        entries: [
          { productId: 0x0091, buildNumber: 0x1c87, count: 12 },
          { productId: 0x1111, buildNumber: 0x2222, count: 5 }
        ],
        warnings: ["Example warning"]
      }
    }
  } as unknown as PeParseResult;

  const out: string[] = [];
  renderRichHeader(pe, out);
  const html = out.join("");

  assert.ok(html.includes("Rich header"));
  assert.ok(html.includes("0x12345678"));
  assert.ok(html.includes("Linker"));
  assert.ok(html.includes("VS97 v5.0 SP3 link 5.10.7303"));
  assert.ok(html.includes("Unknown tool"));
  assert.ok(html.includes("Unknown build"));
  assert.ok(html.includes("data-rich-bar"));
  assert.ok(html.includes("Example warning"));
  assert.ok(!html.includes("Show top entries"));
  assert.ok(!html.includes("Show all entries"));
  assert.strictEqual((html.match(/<table/g) ?? []).length, 1);
});
