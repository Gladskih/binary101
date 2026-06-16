"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createArm64ExceptionState,
  recordArm64HandlerRva
} from "../../../../../analyzers/pe/exception/arm64-state.js";

void test("createArm64ExceptionState initializes empty counters and collections", () => {
  const state = createArm64ExceptionState();

  assert.deepEqual(state.beginRvas, []);
  assert.deepEqual(state.handlerRvas, []);
  assert.equal(state.functionCount, 0);
  assert.equal(state.invalidEntryCount, 0);
  assert.equal(state.previousBegin, null);
  assert.equal(state.reportedUnsortedEntries, false);
});

void test("recordArm64HandlerRva keeps non-zero handler RVAs unique in insertion order", () => {
  const state = createArm64ExceptionState();

  recordArm64HandlerRva(state, 0x1234);
  recordArm64HandlerRva(state, 0);
  recordArm64HandlerRva(state, 0x1234);
  recordArm64HandlerRva(state, 0x2000);

  assert.deepEqual(state.handlerRvas, [0x1234, 0x2000]);
  assert.equal(state.handlerRvasSet.size, 2);
});
