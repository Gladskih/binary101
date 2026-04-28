"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { resolveAmd64ExceptionDirectory } from "../../analyzers/pe/exception/amd64/directory.js";
import {
  RUNTIME_FUNCTION_ENTRY_SIZE_BYTES,
  createRvaAllocator
} from "../helpers/pe-amd64-unwind-fixture.js";

const identityRvaToOffset = (rva: number): number => rva;

void test("resolveAmd64ExceptionDirectory treats missing and empty directories as absent", () => {
  assert.deepEqual(resolveAmd64ExceptionDirectory(0, [], identityRvaToOffset), {
    kind: "absent"
  });
  assert.deepEqual(
    resolveAmd64ExceptionDirectory(
      RUNTIME_FUNCTION_ENTRY_SIZE_BYTES,
      [{ name: "EXCEPTION", rva: 0, size: 0 }],
      identityRvaToOffset
    ),
    { kind: "absent" }
  );
});

void test("resolveAmd64ExceptionDirectory reports non-empty zero-RVA directories", () => {
  const resolved = resolveAmd64ExceptionDirectory(
    RUNTIME_FUNCTION_ENTRY_SIZE_BYTES,
    [{ name: "EXCEPTION", rva: 0, size: RUNTIME_FUNCTION_ENTRY_SIZE_BYTES }],
    identityRvaToOffset
  );
  assert.strictEqual(resolved.kind, "invalid");
  assert.ok(resolved.kind === "invalid");
  assert.ok(resolved.result.issues.some(issue => /rva is 0/i.test(issue)));
});

void test("resolveAmd64ExceptionDirectory reports directories outside the file", () => {
  const allocator = createRvaAllocator();
  const directoryRva = allocator.allocate(RUNTIME_FUNCTION_ENTRY_SIZE_BYTES);
  const resolved = resolveAmd64ExceptionDirectory(
    directoryRva,
    [{ name: "EXCEPTION", rva: directoryRva, size: RUNTIME_FUNCTION_ENTRY_SIZE_BYTES }],
    () => directoryRva
  );
  assert.strictEqual(resolved.kind, "invalid");
  assert.ok(resolved.kind === "invalid");
  assert.ok(resolved.result.issues.some(issue => /outside the file/i.test(issue)));
});

void test("resolveAmd64ExceptionDirectory reports undersized directories", () => {
  const allocator = createRvaAllocator();
  const directoryRva = allocator.allocate(RUNTIME_FUNCTION_ENTRY_SIZE_BYTES);
  const resolved = resolveAmd64ExceptionDirectory(
    allocator.current(),
    [
      {
        name: "EXCEPTION",
        rva: directoryRva,
        size: RUNTIME_FUNCTION_ENTRY_SIZE_BYTES - Uint8Array.BYTES_PER_ELEMENT
      }
    ],
    identityRvaToOffset
  );
  assert.strictEqual(resolved.kind, "invalid");
  assert.ok(resolved.kind === "invalid");
  assert.ok(resolved.result.issues.some(issue => /smaller than one runtime_function/i.test(issue)));
});

void test("resolveAmd64ExceptionDirectory keeps valid misaligned directory warnings", () => {
  const allocator = createRvaAllocator();
  const directoryRva = allocator.allocate(RUNTIME_FUNCTION_ENTRY_SIZE_BYTES * 2);
  const resolved = resolveAmd64ExceptionDirectory(
    allocator.current(),
    [
      {
        name: "EXCEPTION",
        rva: directoryRva,
        size: RUNTIME_FUNCTION_ENTRY_SIZE_BYTES * 2 + Uint8Array.BYTES_PER_ELEMENT
      }
    ],
    identityRvaToOffset
  );
  assert.strictEqual(resolved.kind, "valid");
  assert.ok(resolved.kind === "valid");
  assert.strictEqual(resolved.entryCount, 2);
  assert.ok(resolved.issues.some(issue => /not a multiple/i.test(issue)));
});
