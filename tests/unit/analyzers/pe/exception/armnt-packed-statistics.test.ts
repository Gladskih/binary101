import assert from "node:assert/strict";
import { test } from "node:test";
import { createArmntPackedStatistics, recordArmntPackedStatistics } from "../../../../../analyzers/pe/exception/armnt-packed-statistics.js";
import { armntPackedWord } from "../../../../fixtures/pe-armnt-unwind.js";

// ARM packed fields and special Stack Adjust encodings:
// https://learn.microsoft.com/en-us/cpp/build/arm-exception-handling#packed-unwind-data
for (const [adjustment, bytes, prolog, epilog] of [[0, 0, 0, 0], [1, 4, 0, 0],
  [0x3f3, 4044, 0, 0], [0x3f4, 4, 1, 0], [0x3f8, 4, 0, 1], [0x3ff, 16, 1, 1]] as const) {
  void test(`ARMNT packed adjustment ${adjustment} distinguishes folding from literal bytes`, () => {
    const statistics = createArmntPackedStatistics();
    recordArmntPackedStatistics(statistics, armntPackedWord() | (adjustment << 22));

    assert.deepEqual(statistics.stackAdjustments, { [bytes]: 1 });
    assert.equal(statistics.prologFoldingCount, prolog);
    assert.equal(statistics.epilogFoldingCount, epilog);
  });
}

for (const [bits, kind] of [[0, "popPc"], [1, "branch16"], [2, "branch32"], [3, "noEpilog"]] as const) {
  void test(`ARMNT packed return mode ${bits} retains its meaning`, () => {
    const statistics = createArmntPackedStatistics();
    recordArmntPackedStatistics(statistics, (armntPackedWord() & ~(3 << 13)) | (bits << 13) | (1 << 20));

    assert.equal(statistics.returnKinds[kind], 1);
    assert.equal(Object.values(statistics.returnKinds).reduce((sum, count) => sum + count, 0), 1);
  });
}

for (const [floating, register, name] of [[0, 0, "r4"], [0, 7, "r4-r11"],
  [1, 0, "d8"], [1, 6, "d8-d14"], [1, 7, "None"]] as const) {
  void test(`ARMNT R/Reg group ${floating}, ${register} describes ${name}`, () => {
    const statistics = createArmntPackedStatistics();
    recordArmntPackedStatistics(statistics,
      (armntPackedWord() & ~((7 << 16) | (1 << 19))) | (register << 16) | (floating << 19));

    assert.deepEqual(statistics.registerGroups, { [name]: 1 });
  });
}

void test("ARMNT packed records accumulate parameter homes, LR saves and r11 frame chains", () => {
  const statistics = createArmntPackedStatistics();
  const word = armntPackedWord() | (1 << 15) | (1 << 20) | (1 << 21);
  recordArmntPackedStatistics(statistics, word);
  recordArmntPackedStatistics(statistics, word);

  assert.equal(statistics.homesParametersCount, 2);
  assert.equal(statistics.savesLinkRegisterCount, 2);
  assert.equal(statistics.frameChainCount, 2);
  assert.deepEqual(statistics.registerGroups, { None: 2 });
  assert.deepEqual(statistics.stackAdjustments, { 0: 2 });
});

void test("ARMNT packed inventories ignore unpacked and reserved words and stay parse-local", () => {
  const statistics = createArmntPackedStatistics();
  recordArmntPackedStatistics(statistics, 0);
  recordArmntPackedStatistics(statistics, 3);

  assert.deepEqual(statistics, { returnKinds: { popPc: 0, branch16: 0, branch32: 0, noEpilog: 0 },
    registerGroups: {}, stackAdjustments: {}, homesParametersCount: 0, savesLinkRegisterCount: 0,
    frameChainCount: 0, prologFoldingCount: 0, epilogFoldingCount: 0 });
  assert.notEqual(createArmntPackedStatistics().registerGroups, statistics.registerGroups);
});

void test("ARMNT packed records preserve the absence of optional frame operations", () => {
  const statistics = createArmntPackedStatistics();
  recordArmntPackedStatistics(statistics, armntPackedWord());

  assert.equal(statistics.homesParametersCount, 0);
  assert.equal(statistics.savesLinkRegisterCount, 0);
  assert.equal(statistics.frameChainCount, 0);
  assert.equal(statistics.prologFoldingCount, 0);
  assert.equal(statistics.epilogFoldingCount, 0);
});
