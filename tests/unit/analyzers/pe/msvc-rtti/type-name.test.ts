"use strict";

import assert from "node:assert/strict";
import test from "node:test";
import type { Demangler, DemangleWithTextResult } from "llvm-msvc-demangle";
import { createFileRangeReader } from "../../../../../analyzers/file-range-reader.js";
import { createMsvcRttiImage } from "../../../../../analyzers/pe/msvc-rtti/image.js";
import {
  createMsvcRttiTypeNameDecoder,
  getMsvcRttiTypeName,
  MsvcRttiDemangleError
} from "../../../../../analyzers/pe/msvc-rtti/type-name.js";
import { MsvcRttiPeFixtureBuilder } from "../../../../fixtures/pe-msvc-rtti-fixture.js";

const createImage = () => {
  const fixture = new MsvcRttiPeFixtureBuilder().build();
  return createMsvcRttiImage(
    createFileRangeReader(fixture.file, 0, fixture.file.size),
    fixture.core.sections,
    fixture.core.opt.ImageBase,
    fixture.core.opt.SizeOfImage
  );
};

const stubDemangler = (result: DemangleWithTextResult): Demangler => ({
  demangle: () => result,
  demangleType: () => result,
  demangleWithText: () => result,
  demangleTypeWithText: () => result
});

void test("LLVM decodes namespace and template names without adding derived parsed fields", async () => {
  const decode = createMsvcRttiTypeNameDecoder();
  const type = { rva: 0x2100, decoratedName: ".?AV?$Box@H@demo@@" };

  assert.equal(await decode(createImage(), type), true);

  assert.equal(getMsvcRttiTypeName(type), "class demo::Box<int>");
  assert.deepEqual(type, { rva: 0x2100, decoratedName: ".?AV?$Box@H@demo@@" });
  assert.equal(getMsvcRttiTypeName({ ...type }), type.decoratedName);
});

void test("initialization is shared within an image and isolated between images", async () => {
  let loads = 0;
  const decode = createMsvcRttiTypeNameDecoder(async () => {
    loads += 1;
    const { loadMsvcRttiDemangler } = await import(
      "../../../../../analyzers/pe/msvc-rtti/load-demangler.node.js"
    );
    return loadMsvcRttiDemangler();
  });
  const image = createImage();
  const first = { rva: 0x2100, decoratedName: ".?AVFirst@@" };
  const second = { rva: 0x2200, decoratedName: ".?AUSecond@@" };

  assert.deepEqual(await Promise.all([decode(image, first), decode(image, second)]), [true, true]);
  assert.equal(loads, 1);
  assert.equal(getMsvcRttiTypeName(first), "class First");
  assert.equal(getMsvcRttiTypeName(second), "struct Second");
  assert.equal(await decode(createImage(), first), true);
  assert.equal(loads, 2);
});

for (const name of [".?AV?$Box@?@demo@@", ".?AVClass@@tail", ".H", ".?ATUnion@@", ".?AW4Enum@@"]) {
  void test(`LLVM rejects invalid or non-class RTTI candidates: ${name}`, async () => {
    const type = { rva: 0x2100, decoratedName: name };

    const accepted = await createMsvcRttiTypeNameDecoder()(createImage(), type);

    assert.equal(accepted, false);
    assert.equal(getMsvcRttiTypeName(type), name);
  });
}

void test("a partial LLVM result never supplies a displayed or accepted name", async () => {
  const decode = createMsvcRttiTypeNameDecoder(async () => stubDemangler({
    status: "partial", consumed: 8, warnings: ["trailing input"], text: "class Prefix",
    ast: { root: 0, nodes: [{ kind: "TagType", quals: [], qualifiedName: null, tag: "Class" }] }
  }));
  const type = { rva: 0x2100, decoratedName: ".?AVPrefix@@tail" };

  assert.equal(await decode(createImage(), type), false);
  assert.equal(getMsvcRttiTypeName(type), type.decoratedName);
});

void test("a missing AST root cannot confirm a class", async () => {
  const decode = createMsvcRttiTypeNameDecoder(async () => stubDemangler({
    status: "success", consumed: 8, warnings: [], text: "class Broken",
    ast: { root: 0, nodes: [] }
  }));

  assert.equal(await decode(createImage(), { rva: 0x2100, decoratedName: ".?AVBroken@@" }), false);
});

for (const status of ["error", "limit"] as const) {
  void test(`LLVM ${status} results report a visible analysis failure`, async () => {
    const decode = createMsvcRttiTypeNameDecoder(async () => stubDemangler({
      status, consumed: 0, warnings: ["WASM could not finish", "instance quarantined"],
      ast: null, text: null
    }));

    await assert.rejects(
      decode(createImage(), { rva: 0x2100, decoratedName: ".?AVBroken@@" }),
      new MsvcRttiDemangleError(
        "MSVC RTTI name analysis failed: WASM could not finish; instance quarantined"
      )
    );
  });
}

void test("an LLVM error without warnings retains its status", async () => {
  const decode = createMsvcRttiTypeNameDecoder(async () => stubDemangler({
    status: "error", consumed: 0, warnings: [], ast: null, text: null
  }));

  await assert.rejects(
    decode(createImage(), { rva: 0x2100, decoratedName: ".?AVBroken@@" }),
    /MSVC RTTI name analysis failed: error/
  );
});

void test("initialization errors are retained per image and a later file can recover", async () => {
  let loads = 0;
  const decode = createMsvcRttiTypeNameDecoder(async () => {
    loads += 1;
    if (loads === 1) throw new Error("WASM unavailable");
    const { loadMsvcRttiDemangler } = await import(
      "../../../../../analyzers/pe/msvc-rtti/load-demangler.node.js"
    );
    return loadMsvcRttiDemangler();
  });
  const image = createImage();
  const type = { rva: 0x2100, decoratedName: ".?AVRecovered@@" };

  await assert.rejects(decode(image, type), /MSVC RTTI name analysis failed: WASM unavailable/);
  await assert.rejects(decode(image, type), /MSVC RTTI name analysis failed: WASM unavailable/);
  assert.equal(loads, 1);
  assert.equal(await decode(createImage(), type), true);
  assert.equal(getMsvcRttiTypeName(type), "class Recovered");
});

void test("non-Error initialization rejections retain useful diagnostics", async () => {
  const decode = createMsvcRttiTypeNameDecoder(() => Promise.reject("loader unavailable"));

  await assert.rejects(
    decode(createImage(), { rva: 0x2100, decoratedName: ".?AVBroken@@" }),
    /MSVC RTTI name analysis failed: loader unavailable/
  );
});
