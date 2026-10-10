import assert from "node:assert/strict";
import { test } from "node:test";
import { readyToRunDebugStatistics } from "../../../../renderers/pe/ready-to-run-debug-statistics.js";

void test("explains debug mappings and variable storage without listing raw addresses", () => {
  const statistics = readyToRunDebugStatistics([{ runtimeFunctionIndex: 0,
    bounds: [{ nativeOffset: 0, ilOffset: -2, source: 0 },
      { nativeOffset: 3, ilOffset: 0, source: 18 }, { nativeOffset: 4, ilOffset: -3, source: 8 }],
    variables: [{ startOffset: 0, endOffset: 3, variableNumber: -3,
      location: { kind: "register", register: 1 } },
    { startOffset: 3, endOffset: 4, variableNumber: 0,
      location: { kind: "stack-byref", baseRegister: 2, offset: -8 } }]
  }]);

  assert.deepEqual(statistics.map(statistic => statistic.value), [1, 3, 1, 1, 1, 1, 1, 2, 1, 1]);
  assert.ok(statistics.every(statistic => statistic.description.length > 20));
  assert.deepEqual(statistics.map(statistic => statistic.label), ["Functions with debug records",
    "Native/IL mappings", "Mappings to IL instructions", "Prolog mappings", "Epilog mappings",
    "Call mappings", "Empty evaluation-stack mappings", "Variable lifetime records",
    "Implicit argument lifetimes", "Indirect variable lifetimes"]);
  assert.equal(readyToRunDebugStatistics([])[0]?.value, 0);
});

void test("counts register and stack indirection but excludes direct storage", () => {
  const statistics = readyToRunDebugStatistics([{ runtimeFunctionIndex: 0, bounds: [], variables: [
    { startOffset: 0, endOffset: 1, variableNumber: -1,
      location: { kind: "register-byref", register: 1 } },
    { startOffset: 0, endOffset: 1, variableNumber: -2,
      location: { kind: "stack-byref", baseRegister: 2, offset: 0 } },
    { startOffset: 0, endOffset: 1, variableNumber: 0,
      location: { kind: "stack", baseRegister: 2, offset: 0 } }
  ] }]);

  assert.equal(statistics[8]?.value, 2);
  assert.equal(statistics[9]?.value, 2);
});
