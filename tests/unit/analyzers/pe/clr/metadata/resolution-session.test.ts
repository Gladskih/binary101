"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { registerClrResolutionSession, getClrResolutionSession }
  from "../../../../../../analyzers/pe/clr/metadata-resolution-session.js";
import { clrResolutionFixture } from "../../../../../helpers/clr-resolution-fixture.js";

void test("keeps decoding sessions outside the plain metadata model", () => {
  const tables = { ...clrResolutionFixture() };
  assert.equal(getClrResolutionSession(tables), undefined);
  const session = { enumTypes: new Map<string, string>(), resolve: () => tables };
  registerClrResolutionSession(tables, session);
  assert.strictEqual(getClrResolutionSession(tables), session);
  assert.equal("resolve" in tables, false);
  assert.equal(getClrResolutionSession({ ...tables }), undefined);
});
