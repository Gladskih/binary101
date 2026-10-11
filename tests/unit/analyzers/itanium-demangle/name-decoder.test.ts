import assert from "node:assert/strict";
import { test } from "node:test";
import type { Demangler, DemangleWithTextResult } from "llvm-itanium-demangle";
import { createItaniumNameDecoder } from "../../../../analyzers/itanium-demangle/name-decoder.js";
import { loadItaniumDemangler } from "../../../../analyzers/itanium-demangle/load.node.js";

const fixedDemangler = (result: DemangleWithTextResult): Demangler => ({
  demangle: () => result, demangleType: () => result,
  demangleWithText: () => result, demangleTypeWithText: () => result
});

void test("legacy Rust-shaped names cannot prove C++ data", async () => {
  // rustc legacy.rs SymbolPath::finish appends a 16-digit hash, then E.
  // https://doc.rust-lang.org/nightly/nightly-rustc/src/rustc_symbol_mangling/legacy.rs.html
  const decoder = createItaniumNameDecoder(assert.fail);

  assert.deepEqual(await decoder.symbol("_ZN4demo3run17h0123456789abcdefE"),
    { text: "demo::run::h0123456789abcdef", symbolKind: undefined });
  assert.equal((await decoder.symbol("_ZN4demo5valueE"))?.symbolKind, "ItaniumData");
  assert.equal((await decoder.symbol("_Z1aI17h0123456789abcdefE"))?.symbolKind, "ItaniumData");
  assert.equal((await decoder.symbol("_ZN4demo1aI17h0123456789abcdefEE"))?.symbolKind, "ItaniumData");
});

void test("symbols and bare types share lazy initialization and cache each parse", async () => {
  const api = await loadItaniumDemangler();
  let loads = 0;
  let symbols = 0;
  let types = 0;
  const decoder = createItaniumNameDecoder(assert.fail, async () => {
    loads += 1;
    return { ...api, demangleWithText(name) { symbols += 1; return api.demangleWithText(name); },
      demangleTypeWithText(name) { types += 1; return api.demangleTypeWithText(name); } };
  });

  assert.equal(await decoder.symbol(undefined), null);
  assert.equal(await decoder.symbol("plain"), null);
  assert.equal(await decoder.symbol("i"), null);
  assert.equal(loads, 0);
  const results = await Promise.all([decoder.symbol("_Z1fi"), decoder.symbol("_Z1fi")]);
  assert.deepEqual(results.map(result => result?.text), ["f(int)", "f(int)"]);
  assert.equal((await decoder.type("N4demo6WidgetE"))?.text, "demo::Widget");
  assert.equal((await decoder.type("N4demo6WidgetE"))?.text, "demo::Widget");
  assert.equal(await decoder.symbol("_Zbroken"), null);
  assert.equal(await decoder.symbol("_Zbroken"), null);
  assert.equal(loads, 1);
  assert.equal(symbols, 2);
  assert.equal(types, 1);
});

void test("only positive data AST kinds exclude exports from code seeds", async () => {
  const decoder = createItaniumNameDecoder(assert.fail);

  assert.equal((await decoder.symbol("_Z5value"))?.symbolKind, "ItaniumData");
  assert.equal((await decoder.symbol("_ZTVN4demo6WidgetE"))?.symbolKind, "ItaniumData");
  assert.equal((await decoder.symbol("_ZTC1A0_1B"))?.symbolKind, "ItaniumData");
  assert.equal((await decoder.symbol("_Z1fi"))?.symbolKind, undefined);
  assert.equal((await decoder.symbol("_ZThn8_N1A1fEv"))?.symbolKind, undefined);
  assert.equal((await decoder.symbol("_ZTH1a"))?.symbolKind, undefined);
});

for (const name of ["_ZTT1A", "_ZTI1A", "_ZTS1A", "_ZGV1a", "_ZGR1a_", "_ZTALi1E"]) {
  void test(`ABI special data ${name} is excluded from code seeds`, async () => {
    const decoder = createItaniumNameDecoder(assert.fail);

    assert.equal((await decoder.symbol(name))?.symbolKind, "ItaniumData");
  });
}

void test("malformed, trailing, overflowing and control-containing encodings stay invalid", async () => {
  const decoder = createItaniumNameDecoder(assert.fail);

  assert.equal(await decoder.symbol("_Z1fiTAIL"), null);
  assert.equal(await decoder.symbol("_Z4294967297Av"), null);
  assert.equal(await decoder.symbol("_Z1fP1AS1Z141Z4_"), null);
  assert.equal(await decoder.symbol("_Z1fi\0"), null);
  assert.equal(await decoder.type("N4demo6Widget"), null);
});

for (const status of ["error", "limit"] as const) {
  for (const warnings of [[], ["native failure"]]) {
    void test(`${status} reports ${warnings.length} native warnings once and quarantines the session`, async () => {
      const failures: string[] = [];
      const decoder = createItaniumNameDecoder(message => failures.push(message), async () =>
        fixedDemangler({ status, consumed: 0, ast: null, text: null, warnings }));

      assert.equal(await decoder.symbol("_Z1fi"), null);
      assert.equal(await decoder.type("i"), null);
      assert.deepEqual(failures, [warnings[0] ?? status]);
    });
  }
}

void test("non-Error loader failures are visible and another analysis can recover", async () => {
  const failures: string[] = [];
  const decoder = createItaniumNameDecoder(message => failures.push(message),
    () => Promise.reject("offline"));

  assert.equal(await decoder.symbol("_Z1fi"), null);
  assert.equal(await decoder.symbol("_Z1fi"), null);
  assert.deepEqual(failures, ["offline"]);
  assert.equal((await createItaniumNameDecoder(assert.fail).symbol("_Z1fi"))?.text, "f(int)");
});

void test("concurrent loader failures report once across different inputs", async () => {
  const failures: string[] = [];
  const decoder = createItaniumNameDecoder(message => failures.push(message),
    () => Promise.reject(new Error("offline")));

  assert.deepEqual(await Promise.all([decoder.symbol("_Z1fi"), decoder.type("i")]), [null, null]);
  assert.deepEqual(failures, ["offline"]);
});

void test("native failure reports all warnings and prevents another native call", async () => {
  let calls = 0;
  const failures: string[] = [];
  const api = await loadItaniumDemangler();
  const decoder = createItaniumNameDecoder(message => failures.push(message), async () => ({
    ...api, demangleWithText(name) {
      calls += 1;
      return calls === 1 ? { status: "error", consumed: 0, text: null, ast: null,
        warnings: ["native failure", "context"] } : api.demangleWithText(name);
    }
  }));

  assert.equal(await decoder.symbol("_Z1fi"), null);
  assert.equal(await decoder.symbol("_Z1fv"), null);
  assert.equal(calls, 1);
  assert.deepEqual(failures, ["native failure; context"]);
});

void test("symbol and bare type caches cannot substitute each other's results", async () => {
  const decoder = createItaniumNameDecoder(assert.fail);

  assert.equal((await decoder.symbol("_Z1fi"))?.text, "f(int)");
  assert.equal(await decoder.type("_Z1fi"), null);
});

void test("an unknown AST root does not claim positive data evidence", async () => {
  const decoder = createItaniumNameDecoder(assert.fail, async () => fixedDemangler({
    status: "success", consumed: 6, warnings: [], text: "f()", ast: { root: 0, nodes: [] }
  }));

  assert.deepEqual(await decoder.symbol("_Z1fv"), { text: "f()", symbolKind: undefined });
});
