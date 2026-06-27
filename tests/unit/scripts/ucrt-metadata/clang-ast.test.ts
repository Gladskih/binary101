"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseClangFunctions } from "../../../../scripts/ucrt-metadata/clang-ast.js";

const astJson = (): string => JSON.stringify({
  kind: "TranslationUnitDecl",
  inner: [
    {
      kind: "FunctionDecl",
      name: "abort",
      type: { qualType: "void (void) __attribute__((noreturn))" }
    },
    {
      kind: "FunctionDecl",
      name: "c11_abort",
      type: { qualType: "void (void)" },
      inner: [{ kind: "C11NoReturnAttr" }]
    },
    {
      kind: "FunctionDecl",
      name: "example",
      type: {
        qualType: "int (const char *, char *, int) __attribute__((cdecl))",
        desugaredQualType: "int (const char *, char *, int)"
      },
      inner: [
        { kind: "ParmVarDecl", name: "source", type: { qualType: "const char *" } },
        { kind: "ParmVarDecl", name: "target", type: { qualType: "char *" } },
        { kind: "ParmVarDecl", name: "count", type: { qualType: "int" } }
      ]
    }
  ]
});

void test("parseClangFunctions reads function declarations from JSON AST", () => {
  const functions = parseClangFunctions(astJson(), new Set(["abort", "c11_abort", "example"]));

  assert.deepEqual(functions.get("abort"), {
    name: "abort",
    returnType: "void",
    rawType: "void (void) __attribute__((noreturn))",
    parameters: [],
    callingConvention: "default",
    variadic: false,
    noReturn: true,
    score: 4
  });
  assert.equal(functions.get("c11_abort")?.noReturn, true);
  assert.deepEqual(functions.get("example")?.parameters, [
    { name: "source", type: "const char *" },
    { name: "target", type: "char *" },
    { name: "count", type: "int" }
  ]);
  assert.equal(functions.get("example")?.callingConvention, "cdecl");
  assert.equal(functions.get("example")?.noReturn, false);
});

void test("parseClangFunctions rejects malformed JSON AST", () => {
  assert.throws(() => parseClangFunctions("{", new Set(["abort"])), SyntaxError);
});
