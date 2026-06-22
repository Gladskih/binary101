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
const CALL_REFERENCE_COUNT = 3;
const JUMP_REFERENCE_COUNT = 2;
const AMD64_BITNESS = 64 as const;
const FIRST_IMPORT_FUNCTION_INDEX = 0;
const INVALID_IAT_RVA = 0;

const createPe = (): PeWindowsParseResult => ({
  disassembly: {
    bitness: AMD64_BITNESS,
    bytesSampled: 0,
    bytesDecoded: 0,
    instructionCount: 0,
    invalidInstructionCount: 0,
    directIatReferences: [{
      slotRva: IAT_RVA,
      callReferenceCount: CALL_REFERENCE_COUNT,
      jumpReferenceCount: JUMP_REFERENCE_COUNT
    }],
    instructionSets: [],
    issues: []
  }
}) as unknown as PeWindowsParseResult;

void test("direct IAT reference cells render separate sortable call and jump counts", () => {
  const counts = directIatReferenceCounts(createPe());

  assert.match(
    renderDirectIatRefsCell(
      counts,
      IAT_RVA,
      FIRST_IMPORT_FUNCTION_INDEX,
      BigUint64Array.BYTES_PER_ELEMENT,
      "call"
    ),
    new RegExp(`data-sort-value="${CALL_REFERENCE_COUNT}">${CALL_REFERENCE_COUNT}</td>`)
  );
  assert.match(
    renderDirectIatRefsCell(
      counts,
      IAT_RVA,
      FIRST_IMPORT_FUNCTION_INDEX,
      BigUint64Array.BYTES_PER_ELEMENT,
      "jump"
    ),
    new RegExp(`data-sort-value="${JUMP_REFERENCE_COUNT}">${JUMP_REFERENCE_COUNT}</td>`)
  );
  assert.match(
    renderDirectIatRefsCell(
      counts,
      INVALID_IAT_RVA,
      FIRST_IMPORT_FUNCTION_INDEX,
      BigUint64Array.BYTES_PER_ELEMENT,
      "call"
    ),
    /data-sort-value="0">—<\/td>/
  );
});

void test("direct IAT reference headers explain the distinct static counters", () => {
  const callHtml = renderDirectIatRefsHeader("call");
  const jumpHtml = renderDirectIatRefsHeader("jump");

  assert.ok(callHtml.includes("data-accessible-tooltip"));
  assert.ok(callHtml.includes("Direct CALL refs"));
  assert.ok(callHtml.includes("not a runtime call count"));
  assert.ok(jumpHtml.includes("Direct JMP refs"));
  assert.ok(jumpHtml.includes("import thunk or tail transfer"));
});
