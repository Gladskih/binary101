"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  addMissingManifestNamespaceDeclarations
} from "../../analyzers/pe/resources/preview/manifest-namespace-fallback.js";

const ASM_V1_NAMESPACE = "urn:schemas-microsoft-com:asm.v1";
const ASM_V2_NAMESPACE = "urn:schemas-microsoft-com:asm.v2";
const ASM_V3_NAMESPACE = "urn:schemas-microsoft-com:asm.v3";

void test("addMissingManifestNamespaceDeclarations adds a missing asmv3 declaration", () => {
  const result = addMissingManifestNamespaceDeclarations(
    "<?xml version=\"1.0\"?><!-- leading comment -->" +
    `<assembly xmlns="${ASM_V1_NAMESPACE}" manifestVersion="1.0">` +
    "<asmv3:application /></assembly>"
  );

  assert.equal(
    result,
    "<?xml version=\"1.0\"?><!-- leading comment -->" +
    `<assembly xmlns="${ASM_V1_NAMESPACE}" manifestVersion="1.0" ` +
    `xmlns:asmv3="${ASM_V3_NAMESPACE}"><asmv3:application /></assembly>`
  );
});

void test("addMissingManifestNamespaceDeclarations adds every used known missing prefix", () => {
  const result = addMissingManifestNamespaceDeclarations(
    `<asmv1:assembly xmlns:asmv1="${ASM_V1_NAMESPACE}">` +
    "<asmv2:trustInfo><asmv3:application /></asmv2:trustInfo>" +
    "</asmv1:assembly>"
  );

  assert.equal(
    result,
    `<asmv1:assembly xmlns:asmv1="${ASM_V1_NAMESPACE}" ` +
    `xmlns:asmv2="${ASM_V2_NAMESPACE}" xmlns:asmv3="${ASM_V3_NAMESPACE}">` +
    "<asmv2:trustInfo><asmv3:application /></asmv2:trustInfo></asmv1:assembly>"
  );
});

void test("addMissingManifestNamespaceDeclarations adds a missing asmv1 root declaration", () => {
  const result = addMissingManifestNamespaceDeclarations("<asmv1:assembly />");

  assert.equal(result, `<asmv1:assembly xmlns:asmv1="${ASM_V1_NAMESPACE}" />`);
});

void test("addMissingManifestNamespaceDeclarations inserts before self-closing root slash", () => {
  const result = addMissingManifestNamespaceDeclarations("<asmv3:application />");

  assert.equal(result, `<asmv3:application xmlns:asmv3="${ASM_V3_NAMESPACE}" />`);
});

void test("addMissingManifestNamespaceDeclarations handles compact self-closing roots", () => {
  const result = addMissingManifestNamespaceDeclarations("<asmv3:application/>");

  assert.equal(result, `<asmv3:application xmlns:asmv3="${ASM_V3_NAMESPACE}"/>`);
});

void test("addMissingManifestNamespaceDeclarations ignores markup terminators inside quotes", () => {
  const result = addMissingManifestNamespaceDeclarations(
    "<assembly note='1 > 0' other=\"2 > 1\"><asmv3:application /></assembly>"
  );

  assert.equal(
    result,
    `<assembly note='1 > 0' other="2 > 1" xmlns:asmv3="${ASM_V3_NAMESPACE}">` +
    "<asmv3:application /></assembly>"
  );
});

void test("addMissingManifestNamespaceDeclarations skips doctype declarations before root", () => {
  const result = addMissingManifestNamespaceDeclarations(
    "<!DOCTYPE assembly><assembly><asmv3:application /></assembly>"
  );

  assert.equal(
    result,
    `<!DOCTYPE assembly><assembly xmlns:asmv3="${ASM_V3_NAMESPACE}">` +
    "<asmv3:application /></assembly>"
  );
});

void test("addMissingManifestNamespaceDeclarations leaves complete namespace declarations alone", () => {
  assert.equal(
    addMissingManifestNamespaceDeclarations(
      `<assembly xmlns:asmv3="${ASM_V3_NAMESPACE}"><asmv3:application /></assembly>`
    ),
    null
  );
});

void test("addMissingManifestNamespaceDeclarations ignores unknown prefixes", () => {
  assert.equal(addMissingManifestNamespaceDeclarations("<foo:assembly />"), null);
});

void test("addMissingManifestNamespaceDeclarations ignores unprefixed manifests", () => {
  assert.equal(addMissingManifestNamespaceDeclarations("<assembly />"), null);
});

void test("addMissingManifestNamespaceDeclarations rejects text without a root tag", () => {
  assert.equal(addMissingManifestNamespaceDeclarations("plain manifest text"), null);
});

void test("addMissingManifestNamespaceDeclarations rejects markup without a root tag", () => {
  assert.equal(addMissingManifestNamespaceDeclarations("<!-- comment only -->"), null);
});

void test("addMissingManifestNamespaceDeclarations rejects a trailing opening bracket", () => {
  assert.equal(addMissingManifestNamespaceDeclarations("plain text <"), null);
});

void test("addMissingManifestNamespaceDeclarations rejects a closing tag before root", () => {
  assert.equal(addMissingManifestNamespaceDeclarations("</assembly>"), null);
});

void test("addMissingManifestNamespaceDeclarations rejects a truncated root tag", () => {
  assert.equal(addMissingManifestNamespaceDeclarations("<assembly"), null);
});

void test("addMissingManifestNamespaceDeclarations rejects a truncated comment", () => {
  assert.equal(
    addMissingManifestNamespaceDeclarations("<!-- <assembly><asmv3:application /></assembly>"),
    null
  );
});

void test(
  "addMissingManifestNamespaceDeclarations rejects adversarial comment-only prologs",
  { timeout: 1_000 },
  () => {
    // Thirty adjacent comments made the removed root-tag regex backtrack for seconds.
    assert.equal(addMissingManifestNamespaceDeclarations("<!---->".repeat(30)), null);
  }
);

void test("addMissingManifestNamespaceDeclarations rejects a truncated processing instruction", () => {
  assert.equal(
    addMissingManifestNamespaceDeclarations("<?xml version=\"1.0\"<assembly />"),
    null
  );
});

void test("addMissingManifestNamespaceDeclarations rejects a truncated declaration", () => {
  assert.equal(addMissingManifestNamespaceDeclarations("<!DOCTYPE assembly"), null);
});
