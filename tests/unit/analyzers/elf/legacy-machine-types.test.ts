import assert from "node:assert/strict";
import { test } from "node:test";
import { ELF_MACHINE } from "../../../../analyzers/elf/machine-types.js";
import { ELF_MACHINE_OPTIONS, ELF_MACHINE_LEGACY } from
  "../../../../analyzers/elf/legacy-machine-types.js";

// Independent expected values from GNU binutils include/elf/common.h.
// https://sourceware.org/git/?p=binutils-gdb.git;a=blob;f=include/elf/common.h
const expected = [
  [0xb, "OLD_SPARCV9 (legacy/unofficial)", "SPARC V9 (pre-ABI)"],
  [0x1057, "AVR_OLD (legacy/unofficial)", "AVR"],
  [0x1059, "MSP430_OLD (legacy/unofficial)", "MSP430"],
  [0x1223, "ADAPTEVA_EPIPHANY (legacy/unofficial)", "Adapteva Epiphany"],
  [0x2530, "MT (legacy/unofficial)", "Morpho MT"],
  [0x3330, "CYGNUS_FR30 (legacy/unofficial)", "FR30"],
  [0x4157, "WEBASSEMBLY (legacy/unofficial)", "WebAssembly"],
  [0x4688, "XC16X (legacy/unofficial)", "Infineon C166-V2"],
  [0x4def, "S12Z (legacy/unofficial)", "Freescale S12Z"],
  [0x5441, "CYGNUS_FRV (legacy/unofficial)", "Fujitsu FR-V (EM_FRV in Linux)"],
  [0x5aa5, "DLX (legacy/unofficial)", "DLX"],
  [0x7650, "CYGNUS_D10V (legacy/unofficial)", "D10V"],
  [0x7676, "CYGNUS_D30V (legacy/unofficial)", "D30V"],
  [0x8217, "IP2K_OLD (legacy/unofficial)", "Ubicom IP2xxx"],
  [0x9025, "CYGNUS_POWERPC (legacy/unofficial)", "PowerPC"],
  [0x9026, "ALPHA (legacy/unofficial)", "Alpha"],
  [0x9041, "CYGNUS_M32R (legacy/unofficial)", "M32R"],
  [0x9080, "CYGNUS_V850 (legacy/unofficial)", "V850"],
  [0xa390, "S390_OLD (legacy/unofficial)", "S/390"],
  [0xabc7, "XTENSA_OLD (legacy/unofficial)", "Xtensa"],
  [0xad45, "XSTORMY16 (legacy/unofficial)", "XStormy16"],
  [0xbaab, "MICROBLAZE_OLD (legacy/unofficial)", "MicroBlaze"],
  [0xbeef, "CYGNUS_MN10300 (legacy/unofficial)", "MN10300"],
  [0xdead, "CYGNUS_MN10200 (legacy/unofficial)", "MN10200"],
  [0xf00d, "CYGNUS_MEP (legacy/unofficial)", "Toshiba MeP"],
  [0xfeb0, "M32C_OLD (legacy/unofficial)", "Renesas M32C/M16C"],
  [0xfeba, "IQ2000 (legacy/unofficial)", "Vitesse IQ2000"],
  [0xfebb, "NIOS32 (legacy/unofficial)", "NIOS"],
  [0xfeed, "MOXIE_OLD (legacy/unofficial)", "Moxie"],
];

void test("preserves every non-gABI architecture from the reviewed upstream tables", () => {
  assert.deepEqual(ELF_MACHINE_LEGACY, expected);
  assert.deepEqual(ELF_MACHINE_OPTIONS, [...ELF_MACHINE, ...expected]);
  assert.equal(new Set(ELF_MACHINE_OPTIONS.map(([code]) => code)).size, ELF_MACHINE_OPTIONS.length);
});

void test("keeps gABI assignments authoritative and reserved codes unknown", () => {
  assert.deepEqual(ELF_MACHINE.find(([code]) => code === 257), [257, "65816", "WDC 65816/65C816"]);
  assert.deepEqual(ELF_MACHINE.find(([code]) => code === 258), [258, "LOONGARCH", "Loongson Loongarch"]);
  // gABI Appendix A reserves 182/184; binutils names them but defines no architecture.
  assert.equal(ELF_MACHINE_OPTIONS.some(([code]) => [182, 184, 65535].includes(code)), false);
  assert.equal(ELF_MACHINE_LEGACY.some(([code]) => ELF_MACHINE.some(([official]) =>
    official === code)), false);
});

