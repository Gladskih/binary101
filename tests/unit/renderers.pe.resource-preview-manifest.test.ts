"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  renderManifestPreview,
  renderManifestTree
} from "../../renderers/pe/resource-preview-manifest.js";
import {
  createManifestIncidentalValues,
  createManifestInfoFixture,
  createManifestTextFixture,
  createManifestTreeFixture,
  createManifestValidationFixture
} from "../fixtures/pe-manifest-preview-fixture.js";

// IMAGE_FILE_HEADER.Machine values are defined by the PE/COFF spec and winnt.h.
const AMD64_MACHINE = 0x8664;

void test("renderManifestTree renders nested manifest nodes with expand controls", () => {
  const incidental = createManifestIncidentalValues();
  const info = createManifestInfoFixture(
    {
      requestedExecutionLevel: "requireAdministrator",
      supportedArchitectures: ["amd64", "arm64"]
    },
    incidental
  );
  const tree = createManifestTreeFixture(
    {
      assemblyName: info.assemblyName,
      assemblyVersion: info.assemblyVersion,
      requestedExecutionLevel: "requireAdministrator"
    },
    incidental
  );
  const html = renderManifestTree(info, tree);

  assert.match(html, /Parsed tree/);
  assert.match(html, /Expand all/);
  assert.match(html, /data-manifest-tree-action="expand"/);
  assert.match(html, /data-manifest-tree-action="collapse"/);
  assert.match(html, /<details/);
  assert.match(html, /&lt;assembly&gt;/);
  assert.match(html, /@manifestVersion/);
  assert.match(html, new RegExp(String(info.assemblyName)));
  assert.match(html, /requireAdministrator/);
});

void test("renderManifestTree synthesizes a semantic tree from manifest metadata when XML tree is absent", () => {
  const info = createManifestInfoFixture({
    processorArchitecture: "amd64",
    requestedExecutionLevel: "asInvoker",
    supportedArchitectures: ["amd64", "arm64"]
  });
  const html = renderManifestTree(info, undefined);

  assert.match(html, /assemblyIdentity/);
  assert.match(html, /requestedExecutionLevel/);
  assert.match(html, /supportedArchitectures/);
  assert.match(html, /amd64 arm64/);
});

void test("renderManifestTree disables expand when the tree is already fully open", () => {
  const html = renderManifestTree(
    createManifestInfoFixture(),
    {
      name: "assembly",
      attributes: [],
      text: null,
      children: []
    }
  );

  assert.match(html, /data-manifest-tree-action="expand" disabled/);
  assert.match(html, /data-manifest-tree-action="collapse"/);
});

void test("renderManifestTree annotates well-known supportedOS GUIDs", () => {
  const html = renderManifestTree(
    undefined,
    {
      name: "supportedOS",
      attributes: [{ name: "Id", value: "{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}" }],
      text: null,
      children: []
    }
  );

  assert.match(html, /Windows 10 \/ 11/);
  assert.match(html, /Windows Server 2016/);
});

void test("renderManifestPreview renders manifest validation status and details", () => {
  const html = renderManifestPreview(
    createManifestTextFixture(),
    undefined,
    createManifestTreeFixture({}, createManifestIncidentalValues()),
    createManifestValidationFixture(AMD64_MACHINE, { processorArchitecture: "amd64" })
  );

  assert.match(html, /Manifest cross-check/);
  assert.match(html, /Consistent/);
  assert.match(html, /Checks run/);
  assert.match(html, /Validated details/);
  assert.match(html, /COFF Machine 8664/);
  assert.match(html, /data-manifest-copy-button/);
  assert.doesNotMatch(html, /Raw XML/);
});

void test("renderManifestTree returns an empty string when manifest metadata is absent", () => {
  assert.strictEqual(renderManifestTree(undefined, undefined), "");
});
