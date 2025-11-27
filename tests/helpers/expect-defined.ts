"use strict";

import assert from "node:assert/strict";

export const expectDefined = <T>(value: T | null | undefined, message?: string): T => {
  assert.ok(value !== null && value !== undefined, message ?? "Expected value to be defined");
  return value;
};
