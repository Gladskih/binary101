import assert from "node:assert/strict";
import { test } from "node:test";
import { createRustDlangNameDecoder } from "../../../../analyzers/symbol-demangle/rust-dlang.js";
import { loadRustDemangler, loadDlangDemangler } from
  "../../../../analyzers/symbol-demangle/load.node.js";

void test("unrelated, absent, legacy and decorated names do not load either grammar", async () => {
  const decode = createRustDlangNameDecoder(assert.fail, assert.fail, assert.fail);

  assert.equal(await decode(undefined), null);
  assert.equal(await decode(""), null);
  assert.equal(await decode("Sleep"), null);
  assert.equal(await decode("_ZN4demo4main17h0123456789abcdefE"), null);
  assert.equal(await decode("__RNvC1a4main"), null);
  assert.equal(await decode("?f@@YAHH@Z"), null);
});

void test("concurrent aliases share initialization, successful parsing and invalid parsing", async () => {
  const api = await loadRustDemangler();
  let loads = 0;
  const parsed: string[] = [];
  const decode = createRustDlangNameDecoder(assert.fail, async () => {
    loads += 1;
    return { ...api, demangleWithText(name) {
      parsed.push(name);
      return api.demangleWithText(name);
    } };
  }, assert.fail);

  const results = await Promise.all([decode("_RNvC1a4main"), decode("_RNvC1a4main"),
    decode("_Rbroken"), decode("_Rbroken")]);

  assert.equal(loads, 1);
  assert.deepEqual(parsed, ["_RNvC1a4main", "_Rbroken"]);
  assert.deepEqual(results[0], { text: "a::main", language: "Rust v0", symbolKind: undefined });
  assert.strictEqual(results[0], results[1]);
  assert.equal(results[2], null);
  assert.equal(results[3], null);
});

void test("failed Rust initialization warns once without disabling D or another file", async () => {
  const warnings: string[] = [];
  const decode = createRustDlangNameDecoder(message => warnings.push(message),
    () => Promise.reject(new Error("offline")));

  assert.deepEqual(await Promise.all([decode("_RC1a"), decode("_RC1b")]), [null, null]);
  assert.equal(await decode("_RC1c"), null);
  assert.equal((await decode("_Dmain"))?.text, "D main");
  assert.deepEqual(warnings, ["Rust v0: offline"]);
  assert.equal((await createRustDlangNameDecoder(assert.fail)("_RC1a"))?.text, "a");
});

void test("failed D initialization warns once without disabling Rust", async () => {
  const warnings: string[] = [];
  const decode = createRustDlangNameDecoder(message => warnings.push(message),
    loadRustDemangler, () => Promise.reject("unavailable"));

  assert.equal(await decode("_Dmain"), null);
  assert.equal(await decode("_D3foo3barf"), null);
  assert.equal((await decode("_RC1a"))?.text, "a");
  assert.deepEqual(warnings, ["D: unavailable"]);
});

for (const status of ["error", "limit"] as const) {
  for (const warnings of [[], ["native failure", "context"]]) {
    void test(`${status} with ${warnings.length} diagnostics quarantines only that grammar`, async () => {
      const messages: string[] = [];
      let calls = 0;
      const decode = createRustDlangNameDecoder(message => messages.push(message), async () => ({
        demangle: assert.fail,
        demangleWithText() {
          calls += 1;
          return { status, warnings, ast: null, text: null };
        }
      }));

      assert.equal(await decode("_RC1a"), null);
      assert.equal(await decode("_RC1b"), null);
      assert.equal((await decode("_Dmain"))?.text, "D main");
      assert.equal(calls, 1);
      assert.deepEqual(messages, ["Rust v0: " + (warnings.length ? "native failure; context" : status)]);
    });
  }
}

void test("invalid and unsupported D names are cached without warnings or disabling valid names", async () => {
  const decode = createRustDlangNameDecoder(assert.fail);

  assert.equal(await decode("_D3foo3barFiZi"), null);
  assert.equal(await decode("_D3foo3barFiZi"), null);
  assert.equal(await decode("_D3foo3barftrailing"), null);
  assert.equal((await decode("_D3foo3barf"))?.symbolKind, "DlangData");
});

for (const identifier of ["__init", "__vtbl", "__Class", "__Interface", "__ModuleInfo"]) {
  void test(`D ${identifier} is classified by its special AST production`, async () => {
    // D ABI SpecialName productions; these are data, unlike the separately encoded _Dmain.
    // https://dlang.org/spec/abi.html#name_mangling
    const name = `_D3foo3Bar${identifier.length}${identifier}Z`;

    const decoded = await createRustDlangNameDecoder(assert.fail)(name);

    assert.equal(decoded?.language, "D");
    assert.equal(decoded?.symbolKind, "DlangData");
  });
}

void test("plain D artificial names and D main remain unclassified", async () => {
  const decode = createRustDlangNameDecoder(assert.fail);

  assert.deepEqual(await decode("_Dmain"), { text: "D main", language: "D", symbolKind: undefined });
  assert.deepEqual(await decode("_D3foo3barZ"),
    { text: "foo.bar", language: "D", symbolKind: undefined });
});

void test("a D success with no Symbol root or MangledName cannot prove data", async () => {
  const api = await loadDlangDemangler();
  const parsed = api.demangleWithText("_D3foo3barf");
  assert.equal(parsed.status, "success");
  const decode = createRustDlangNameDecoder(assert.fail, assert.fail, async () => ({ ...api,
    demangleWithText: () => ({ ...parsed, ast: { root: 100, nodes: [] } }) }));
  const main = createRustDlangNameDecoder(assert.fail, assert.fail, async () => ({ ...api,
    demangleWithText: () => ({ ...parsed, ast: { root: 0,
      nodes: [{ kind: "Symbol", start: 0, end: 0, children: [1] }] } }) }));

  assert.equal((await decode("_D3foo3barf"))?.symbolKind, undefined);
  assert.equal((await main("_D3foo3barf"))?.symbolKind, undefined);
});

void test("valid long Rust identifiers have no presentation policy cap", async () => {
  const name = "a".repeat(20_000);

  const decoded = await createRustDlangNameDecoder(assert.fail)("_RC20000" + name);

  assert.equal(decoded?.text, name);
  assert.equal(decoded?.symbolKind, undefined);
});

void test("an unexpected D grammar production cannot promote unrelated types into data", async () => {
  const api = await loadDlangDemangler();
  const decode = createRustDlangNameDecoder(assert.fail, assert.fail, async () => ({ ...api,
    demangleWithText: () => ({ status: "success", text: "unexpected", warnings: [], ast: {
      root: 0, nodes: [
        { kind: "Symbol", start: 0, end: 6, children: [1] },
        { kind: "QualifiedName", start: 0, end: 6, children: [2] },
        { kind: "Type", start: 5, end: 6, children: [], code: "i" }
      ]
    } }) }));

  assert.equal((await decode("_Dmain"))?.symbolKind, undefined);
});
