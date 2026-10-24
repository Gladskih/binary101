import assert from "node:assert/strict";
import { test } from "node:test";
import { renderIa64UnwindStatistics } from "../../../../renderers/pe/exception-ia64.js";
import { createEmptyExceptionDirectory } from "../../../../analyzers/pe/exception/types.js";

void test("IA64 renders descriptor summaries, known flags, versions and exact stack sizes", () => {
  const out: string[] = [];
  renderIa64UnwindStatistics({ ...createEmptyExceptionDirectory([], "ia64"), handlerUnwindInfoCount: 2,
    ia64Unwind: { versions: [{ version: 3, count: 4 }, { version: 99, count: 1 }],
      descriptorCounts: { "Prologue regions": 3, "Body regions": 8, "<bad>": 1 },
      regionLengths: { prologue: { count: 2, minimumSlots: "1", maximumSlots: "128" },
        body: { count: 1, minimumSlots: "5", maximumSlots: "5" } },
      savedRegisterRules: { "branch registers in memory": 4 },
      registerSaveLocations: { "PSP-relative memory spill rules": 2 },
      spillScheduleSlots: { "floating-point registers from spill schedule": 2 },
      abiContextCounts: { "Windows NT context 0x11": 1 },
      exceptionHandlerCount: 2, unwindHandlerCount: 1, maximumFixedStackBytes: 48 }
  }, out);
  const html = out.join("");

  assert.match(html, /IA64 unwind version 3 blocks<\/dt><dd>4<\/dd>/);
  assert.match(html, /IA64 unwind version 99 blocks<\/dt><dd>1<\/dd>/);
  assert.match(html, /Decoded unwind blocks with handlers<\/dt><dd>2<\/dd>/);
  assert.match(html, /Exception-handler blocks<\/dt><dd>2<\/dd>/);
  assert.match(html, /Cleanup-handler blocks<\/dt><dd>1<\/dd>/);
  assert.match(html, /Prologue regions<\/dt><dd>3<\/dd>/);
  assert.match(html, /Body regions<\/dt><dd>8<\/dd>/);
  assert.match(html, /IA64 Prologue region length \(instruction slots\)<\/dt><dd>1 to 128 across 2 regions<\/dd>/);
  assert.match(html, /Saved register rules: branch registers in memory<\/dt><dd>4<\/dd>/);
  assert.match(html, /IA64 register save location: PSP-relative memory spill rules<\/dt><dd>2<\/dd>/);
  assert.match(html, /P4 spill schedule slots: floating-point registers from spill schedule<\/dt><dd>2<\/dd>/);
  assert.match(html, /P10 ABI context: Windows NT context 0x11<\/dt><dd>1<\/dd>/);
  assert.match(html, /&lt;bad><\/dt><dd>1<\/dd>/);
  assert.match(html, /Largest fixed stack allocation \(bytes\)<\/dt><dd>48<\/dd>/);
});

void test("IA64 omits unavailable statistics but retains a real zero stack allocation", () => {
  const absent: string[] = [], empty: string[] = [], zero: string[] = [];
  renderIa64UnwindStatistics(createEmptyExceptionDirectory([], "ia64"), absent);
  renderIa64UnwindStatistics({ ...createEmptyExceptionDirectory([], "ia64"),
    ia64Unwind: { versions: [], descriptorCounts: {}, regionLengths: { prologue: { count: 0 }, body: { count: 0 } },
      savedRegisterRules: {}, registerSaveLocations: {}, spillScheduleSlots: {}, abiContextCounts: {},
      exceptionHandlerCount: 0, unwindHandlerCount: 0 }
  }, empty);
  renderIa64UnwindStatistics({ ...createEmptyExceptionDirectory([], "ia64"),
    ia64Unwind: { versions: [], descriptorCounts: {}, regionLengths: { prologue: { count: 0 }, body: { count: 0 } },
      savedRegisterRules: {}, registerSaveLocations: {}, spillScheduleSlots: {}, abiContextCounts: {},
      exceptionHandlerCount: 0,
      unwindHandlerCount: 0, maximumFixedStackBytes: 0 }
  }, zero);

  assert.deepEqual(absent, []);
  assert.doesNotMatch(empty.join(""), /Largest fixed stack allocation/);
  assert.match(zero.join(""), /Largest fixed stack allocation \(bytes\)<\/dt><dd>0<\/dd>/);
});
