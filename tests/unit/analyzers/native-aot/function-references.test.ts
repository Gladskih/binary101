import assert from "node:assert/strict";
import test from "node:test";
import { NativeAotFunctionReferences } from "../../../../analyzers/native-aot/function-references.js";
import { createFunctionEntryFixture } from "../../../helpers/native-aot-function-map-fixture.js";

void test("function reference context shares lazy tables and pointer caches", () => {
  const fixture = createFunctionEntryFixture(new Uint8Array());
  const references = new NativeAotFunctionReferences(fixture.image, [], fixture.issues);

  assert.equal(fixture.issues.size, 0);
  assert.equal(references.common, references.common);
  assert.equal(references.native, references.native);
  assert.equal(references.statics, references.statics);
  assert.notEqual(references.common, references.native);
  assert.deepEqual([...fixture.issues], ["Common fixups table is missing or ambiguous.",
    "Native references table is missing or ambiguous.", "Native statics table is missing or ambiguous."]);
});
