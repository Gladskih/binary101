"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { addManifestPreviewWithXmlParser } from "../../analyzers/pe/resources/preview/manifest.js";
import { parseManifestTestXmlDocument } from "../helpers/manifest-test-parser.js";
import {
  createInvalidUiAccessManifestXmlFixture,
  createManifestIncidentalValues,
  createManifestXmlFixture,
  createMalformedManifestXmlFixture,
  createPrefixedManifestXmlFixture
} from "../fixtures/pe-manifest-preview-fixture.js";

const encoder = new TextEncoder();

void test("addManifestPreviewWithXmlParser extracts assembly identity and execution metadata", () => {
  const fixture = createManifestXmlFixture(
    {
      processorArchitecture: "amd64",
      requestedExecutionLevel: "requireAdministrator",
      supportedArchitectures: ["amd64", "arm64"]
    },
    createManifestIncidentalValues()
  );
  const result = addManifestPreviewWithXmlParser(
    encoder.encode(fixture.xml),
    "MANIFEST",
    65001,
    parseManifestTestXmlDocument
  );

  assert.equal(result?.preview?.previewKind, "text");
  assert.equal(result?.preview?.manifestInfo?.manifestVersion, fixture.manifestInfo.manifestVersion);
  assert.equal(result?.preview?.manifestInfo?.assemblyName, fixture.manifestInfo.assemblyName);
  assert.equal(result?.preview?.manifestInfo?.assemblyVersion, fixture.manifestInfo.assemblyVersion);
  assert.equal(result?.preview?.manifestInfo?.processorArchitecture, "amd64");
  assert.equal(result?.preview?.manifestInfo?.requestedExecutionLevel, "requireAdministrator");
  assert.equal(result?.preview?.manifestInfo?.requestedUiAccess, false);
  assert.deepEqual(result?.preview?.manifestInfo?.supportedArchitectures, ["amd64", "arm64"]);
  assert.equal(result?.preview?.manifestTree?.name, "assembly");
  assert.equal(result?.preview?.manifestTree?.attributes[0]?.name, "manifestVersion");
  assert.equal(result?.preview?.manifestTree?.children[0]?.name, "assemblyIdentity");
});

void test("addManifestPreviewWithXmlParser preserves parser issues for malformed manifests", () => {
  const result = addManifestPreviewWithXmlParser(
    encoder.encode(createMalformedManifestXmlFixture({ processorArchitecture: "x86" })),
    "MANIFEST",
    65001,
    parseManifestTestXmlDocument
  );

  assert.equal(result?.preview?.previewKind, "text");
  assert.equal(result?.preview?.manifestInfo, undefined);
  assert.equal(result?.preview?.manifestTree, undefined);
  assert.ok(result?.issues?.some(issue => /XML parser/i.test(issue)));
});

void test("addManifestPreviewWithXmlParser reports invalid uiAccess values", () => {
  const result = addManifestPreviewWithXmlParser(
    encoder.encode(
      createInvalidUiAccessManifestXmlFixture({
        processorArchitecture: "x86",
        requestedExecutionLevel: "asInvoker"
      })
    ),
    "MANIFEST",
    65001,
    parseManifestTestXmlDocument
  );

  assert.equal(result?.preview?.manifestInfo?.processorArchitecture, "x86");
  assert.equal(result?.preview?.manifestTree?.children[1]?.name, "trustInfo");
  assert.ok(result?.issues?.some(issue => /uiAccess/i.test(issue)));
});

void test("addManifestPreviewWithXmlParser parses namespace-prefixed roots and reports empty supportedArchitectures", () => {
  const fixture = createPrefixedManifestXmlFixture(createManifestIncidentalValues(), {
    processorArchitecture: "amd64"
  });
  const result = addManifestPreviewWithXmlParser(
    encoder.encode(fixture.xml),
    "MANIFEST",
    65001,
    parseManifestTestXmlDocument
  );

  assert.equal(result?.preview?.manifestInfo?.assemblyName, fixture.manifestInfo.assemblyName);
  assert.equal(result?.preview?.manifestInfo?.processorArchitecture, "amd64");
  assert.deepEqual(result?.preview?.manifestInfo?.supportedArchitectures, []);
  assert.equal(result?.preview?.manifestTree?.name, "asmv1:assembly");
  assert.equal(result?.preview?.manifestTree?.children[1]?.name, "asmv3:application");
  assert.ok(result?.issues?.includes(
    "Manifest supportedArchitectures element is present but empty."
  ));
});
