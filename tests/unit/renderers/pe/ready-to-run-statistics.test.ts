import assert from "node:assert/strict";
import test from "node:test";
import { readyToRunStatistics, readyToRunSectionStatistics } from
  "../../../../renderers/pe/ready-to-run-statistics.js";
import { createReadyToRunRendererFixture } from "../../../helpers/ready-to-run-renderer-fixture.js";

void test("summaries describe import signatures, fixups, composite headers and hot/cold code", () => {
  const data = createReadyToRunRendererFixture();

  const statistics = readyToRunStatistics(data.sections);

  assert.deepEqual(statistics.map(statistic => statistic.label), ["Import tables", "Import cells",
    "Import cells with signatures", "Method-definition entry points", "Methods with fixups", "Component assemblies",
    "Decoded component headers", "Hot/cold code pairs"]);
  assert.deepEqual(statistics.map(statistic => statistic.value), [1, 2, 1, 2, 1, 1, 0, 1]);
  assert.deepEqual(readyToRunSectionStatistics(data.sections[5]!), []);
  assert.deepEqual(readyToRunSectionStatistics(data.sections[0]!), []);
  assert.ok(statistics.every(statistic => statistic.description.length > 20));
});

void test("generic methods and thunk kinds are summarized without retaining an address display", () => {
  const section = createReadyToRunRendererFixture().sections[2]!;

  const generic = readyToRunSectionStatistics({ ...section, decoded: { kind: "instance-methods", methods: [
    { signatureOffset: 1, runtimeFunctionIndex: 0, fixupOffset: null }
  ] } });
  assert.deepEqual(generic.map(statistic => [statistic.label, statistic.value]), [
    ["Instantiated method entry points", 1], ["Methods with fixups", 0]
  ]);
  assert.equal(generic[0]?.description, "Compiled generic instantiations identified by native signatures.");
  assert.equal(readyToRunSectionStatistics(section)[0]?.description,
    "Compiled methods linked to managed method definitions.");
  const statistics = readyToRunSectionStatistics({ ...section, decoded: { kind: "thunks", entries: [
    { rva: 0x400, size: 6, kind: "eager", helperCellRva: 0x600 },
    { rva: 0x420, size: 6, kind: "eager", helperCellRva: 0x600 },
    { rva: 0x440, size: 20, kind: "virtual-dispatch", helperCellRva: null }
  ] } });
  assert.deepEqual(statistics.map(statistic => [statistic.label, statistic.value]), [
    ["Import thunks", 3], ["eager thunks", 2], ["virtual-dispatch thunks", 1]
  ]);
  assert.ok(statistics.every(statistic => statistic.description.length > 20));
});

void test("decoded component and signed import-cell counts distinguish present and missing records", () => {
  const data = createReadyToRunRendererFixture();
  const components = data.sections[3]!.decoded!;
  const imports = data.sections[1]!.decoded!;
  assert.equal(components.kind, "components");
  assert.equal(imports.kind, "imports");
  components.entries[0]!.coreHeader = { flags: 0, sectionCount: 0, sections: [] };
  imports.imports[0]!.entries.push({ value: new Uint8Array(4), signatureRva: 0x400 });

  assert.equal(readyToRunSectionStatistics(data.sections[3]!)[1]?.value, 1);
  assert.equal(readyToRunSectionStatistics(data.sections[1]!)[2]?.value, 2);
});

void test("multiple component payloads aggregate matching metrics", () => {
  const sections = createReadyToRunRendererFixture().sections;

  const statistics = readyToRunStatistics([...sections, sections[2]!]);

  assert.equal(statistics.find(statistic => statistic.label === "Method-definition entry points")?.value, 4);
  assert.equal(statistics.find(statistic => statistic.label === "Methods with fixups")?.value, 2);
});
