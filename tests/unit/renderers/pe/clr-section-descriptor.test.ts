import assert from "node:assert/strict";
import test from "node:test";
import { getPeClrSectionDescriptor } from "../../../../renderers/pe/clr-section-descriptor.js";
import { createBasePe } from "../../../fixtures/pe-renderer-headers-fixture.js";
import { createReadyToRunCompositeFixture } from "../../../helpers/ready-to-run-composite-fixture.js";
import type { PeClrHeader } from "../../../../analyzers/pe/clr/types.js";

void test("exposes CLR-free composite headers and omits absent runtime metadata", () => {
  const pe = createBasePe();

  assert.equal(getPeClrSectionDescriptor(pe), null);
  pe.readyToRun = createReadyToRunCompositeFixture().data;
  assert.deepEqual(getPeClrSectionDescriptor(pe),
    { key: "clr", title: "ReadyToRun composite header", summary: "2 ReadyToRun sections" });
});

void test("keeps CLR runtime summaries and compact metadata row counts", () => {
  const pe = createBasePe();
  pe.clr = { ...createReadyToRunCompositeFixture().clr, MajorRuntimeVersion: 2, MinorRuntimeVersion: 5 };

  assert.deepEqual(getPeClrSectionDescriptor(pe),
    { key: "clr", title: "CLR (.NET) header", summary: "runtime v2.5" });
  pe.clr.meta = { streams: [], tables: { rowCounts: [{ rows: 125, table: "TypeDef" }] } } as
    unknown as NonNullable<PeClrHeader["meta"]>;
  assert.equal(getPeClrSectionDescriptor(pe)?.summary, "CLR metadata: 125 rows");
  pe.clr.meta!.tables!.rowCounts[0]!.rows = 15000;
  assert.equal(getPeClrSectionDescriptor(pe)?.summary, "CLR metadata: 15k rows");
  pe.clr.meta!.tables!.rowCounts[0]!.rows = 10000;
  assert.equal(getPeClrSectionDescriptor(pe)?.summary, "CLR metadata: 10k rows");
  pe.clr.meta = {} as NonNullable<PeClrHeader["meta"]>;
  assert.equal(getPeClrSectionDescriptor(pe)?.summary, "runtime v2.5");
  pe.clr = {} as PeClrHeader;
  assert.equal(getPeClrSectionDescriptor(pe)?.summary, "runtime v0.0");
});
