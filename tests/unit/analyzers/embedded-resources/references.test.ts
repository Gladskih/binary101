import assert from "node:assert/strict";
import { test } from "node:test";
import { addResourceReferenceEvidence } from "../../../../analyzers/embedded-resources/references.js";
import { detectEmbeddedResources } from "../../../../analyzers/embedded-resources/detect.js";
import { embeddedResourceFixture, minimalRcc } from "../../../fixtures/embedded-resource-builders.js";
import { MockFile } from "../../../helpers/mock-file.js";

void test("adds deduplicated evidence for confirmed Qt table and GVDB addresses only", async () => {
  const fixture = minimalRcc();
  const result = await detectEmbeddedResources(new MockFile(fixture.bytes),
    [{ name: ".data", offset: 0, size: fixture.bytes.length }], [], [
      { targetOffset: fixture.tree, description: "tree" }, { targetOffset: fixture.names, description: "names" },
      { targetOffset: fixture.data, description: "data" }, { targetOffset: fixture.tree, description: "tree" },
      { targetOffset: 0, description: "package" }, { targetOffset: 1, description: "unrelated" }
    ]);
  assert.ok(result);
  assert.deepEqual(result.bundles[0]?.evidence.slice(1), ["package", "tree", "names", "data"]);
  const bytes = embeddedResourceFixture("oracle.gresource");
  const glib = await detectEmbeddedResources(new MockFile(bytes), [{ name: ".data", offset: 0, size: bytes.length }], []);
  assert.ok(glib);
  addResourceReferenceEvidence(glib, [{ targetOffset: 0, description: "pointer" }]);
  assert.deepEqual(glib.bundles[0]?.evidence.slice(1), ["pointer"]);
  const empty = { bundles: [], issues: [] };
  addResourceReferenceEvidence(empty, [{ targetOffset: 0, description: "alone" }]);
  assert.deepEqual(empty, { bundles: [], issues: [] });
});
