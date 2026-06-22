"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { PeWindowsParseResult } from "../../../../analyzers/pe/index.js";
import {
  directIatReferenceCounts,
  renderDirectIatRefsCell,
  renderDirectIatRefsHeader
} from "../../../../renderers/pe/direct-iat-references.js";

const IAT_RVA = 0x2000;
const REFERENCE_COUNT = 3;
const AMD64_BITNESS = 64 as const;
const FIRST_IMPORT_FUNCTION_INDEX = 0;
const MISSING_IAT_RVA = 0;

const createPe = (): PeWindowsParseResult => ({
  disassembly: {
    bitness: AMD64_BITNESS,
    bytesSampled: 0,
    bytesDecoded: 0,
    instructionCount: 0,
    invalidInstructionCount: 0,
    directIatReferences: [{ slotRva: IAT_RVA, referenceCount: REFERENCE_COUNT }],
    instructionSets: [],
    issues: []
  }
}) as unknown as PeWindowsParseResult;

void test("direct IAT reference cells render counts and sortable dashes", () => {
  const counts = directIatReferenceCounts(createPe());

  assert.match(
    renderDirectIatRefsCell(
      counts,
      IAT_RVA,
      FIRST_IMPORT_FUNCTION_INDEX,
      BigUint64Array.BYTES_PER_ELEMENT
    ),
    new RegExp(`data-sort-value="${REFERENCE_COUNT}">${REFERENCE_COUNT}</td>`)
  );
  assert.match(
    renderDirectIatRefsCell(
      counts,
      MISSING_IAT_RVA,
      FIRST_IMPORT_FUNCTION_INDEX,
      BigUint64Array.BYTES_PER_ELEMENT
    ),
    /data-sort-value="0">—<\/td>/
  );
});

void test("direct IAT reference header explains static counter semantics", () => {
  const html = renderDirectIatRefsHeader();

  assert.ok(html.includes("data-accessible-tooltip"));
  assert.ok(html.includes("not a runtime call count"));
  assert.ok(html.includes("does not expand shared import thunks"));
});
