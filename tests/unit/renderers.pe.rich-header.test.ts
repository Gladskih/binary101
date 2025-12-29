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

void test("renderRichHeader renders a compact summary and entry tables", () => {
  const pe = {
    dos: {
      stub: { kind: "none", note: "" },
      rich: {
        xorKey: 0x12345678,
        checksum: 0x0,
        entries: [
          { productId: 0x1111, buildNumber: 0x2222, count: 5 },
          { productId: 0x3333, buildNumber: 0x4444, count: 12 },
          { productId: 0x5555, buildNumber: 0x6666, count: 1 },
          { productId: 0x7777, buildNumber: 0x8888, count: 2 },
          { productId: 0x9999, buildNumber: 0xaaaa, count: 3 },
          { productId: 0xbbbb, buildNumber: 0xcccc, count: 4 }
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
  assert.ok(html.includes("Show top entries"));
  assert.ok(html.includes("Show all entries"));
  assert.ok(html.includes("Example warning"));
});
