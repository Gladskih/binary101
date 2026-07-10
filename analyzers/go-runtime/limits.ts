"use strict";

// Defensive local resource ceilings. Values above these are rejected as untrusted metadata rather
// than allowed to trigger very large browser allocations.
export const GO_RUNTIME_MAX_ENTRY_COUNT = 1_000_000;
export const GO_RUNTIME_MAX_TABLE_BYTE_LENGTH = 64 * 1024 * 1024;
