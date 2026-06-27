"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createUcrtEntry } from "../../../../scripts/ucrt-metadata/signature-format.js";
import type { ClangFunctionDecl } from "../../../../scripts/ucrt-metadata/clang-ast.js";

const declaration = (): ClangFunctionDecl => ({
  name: "example",
  returnType: "int",
  rawType: "int (const char *, char *, int)",
  parameters: [
    { name: "source", type: "const char *" },
    { name: "target", type: "char *" },
    { name: "count", type: "int" }
  ],
  callingConvention: "cdecl",
  variadic: false,
  noReturn: false,
  score: 0
});

void test("createUcrtEntry infers parameter direction from C types", () => {
  const entry = createUcrtEntry("ucrtbase.dll", "example", declaration());

  assert.deepEqual(entry.parameters.map(parameter => parameter.direction), ["in", "inout", "in"]);
});
