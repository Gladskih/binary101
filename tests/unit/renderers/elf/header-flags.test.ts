import assert from "node:assert/strict";
import { test } from "node:test";
import { renderElfHeaderFlags } from "../../../../renderers/elf/header-flags.js";
import { readElfFileHeader } from "../../../../analyzers/elf/file-header.js";
import { renderHeader } from "../../../../renderers/elf/index.js";
import { createElfFile } from "../../../fixtures/elf-sample-file.js";
import { MockFile } from "../../../helpers/mock-file.js";
import type { ElfHeader, ElfIdent } from "../../../../analyzers/elf/types.js";

const header: ElfHeader = {
  type: 2, typeName: null, machine: 62, machineName: null, entry: 0n, phoff: 0n,
  shoff: 0n, flags: 0, ehsize: 64, phentsize: 0, phnum: 0, shentsize: 0,
  shnum: 0, shstrndx: 0
};
const ident: ElfIdent = {
  classByte: 2, className: "ELF64", dataByte: 1, dataName: "LSB", osabi: 0, abiVersion: 0
};
const renderFlags = (machine: number, flags: number, osabi = 0, abiVersion = 0): string =>
  renderElfHeaderFlags({ ...header, machine, flags }, { ...ident, osabi, abiVersion });
const chips = (html: string): Map<string, string> =>
  new Map([...html.matchAll(/<span class="opt (sel|dim)"[^>]*>([^<]+)<\/span>/g)]
    .map(match => [match[2]!, match[1]!]));

const fileWithFlags = (classByte: 1 | 2, dataByte: 1 | 2, flags: number): MockFile => {
  // gABI Elf32_Ehdr/Elf64_Ehdr layouts; e_flags is an unsigned word in both.
  // https://gabi.xinuos.com/elf/02-eheader.html
  const layout = { 1: { size: 52, flagsOffset: 36 }, 2: { size: 64, flagsOffset: 48 } }[classByte];
  const bytes = new Uint8Array(layout.size);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, 0x7f454c46);
  bytes.set([classByte, dataByte, 1], 4);
  view.setUint16(16, 1, dataByte === 1);
  view.setUint16(18, 243, dataByte === 1);
  view.setUint32(20, 1, dataByte === 1);
  view.setUint32(layout.flagsOffset, flags, dataByte === 1);
  view.setUint16(layout.flagsOffset + 4, layout.size, dataByte === 1);
  return new MockFile(bytes);
};

for (const [classByte, dataByte] of [[1, 1], [1, 2], [2, 1], [2, 2]] as const) {
  void test(`ELF class ${classByte}, byte order ${dataByte} preserves flags through the UI`, async () => {
    const elf = await readElfFileHeader(fileWithFlags(classByte, dataByte, 0x80000005));
    assert.ok(elf);
    assert.equal(elf.header.flags, 0x80000005);
    const html = renderElfHeaderFlags(elf.header, elf.ident);
    assert.equal(chips(html).get("EF_RISCV_FLOAT_ABI_DOUBLE"), "sel");
    assert.equal(chips(html).get("UNKNOWN_BITS_0x80000000"), "sel");
  });
}

// Numeric oracles: RISC-V psABI, ELF header e_flags (FLOAT_ABI mask = 0x6).
// https://riscv-non-isa.github.io/riscv-elf-psabi-doc/#-file-header
void test("renders every RISC-V flag and exactly one floating-point ABI", () => {
  const html = renderFlags(243, 0x17);
  const states = chips(html);
  assert.equal(states.get("EF_RISCV_RVC"), "sel");
  assert.equal(states.get("EF_RISCV_RVE"), "dim");
  assert.equal(states.get("EF_RISCV_TSO"), "sel");
  assert.equal(states.get("EF_RISCV_FLOAT_ABI_SOFT"), "dim");
  assert.equal(states.get("EF_RISCV_FLOAT_ABI_SINGLE"), "dim");
  assert.equal(states.get("EF_RISCV_FLOAT_ABI_DOUBLE"), "dim");
  assert.equal(states.get("EF_RISCV_FLOAT_ABI_QUAD"), "sel");
  assert.match(html, /0x00000017/);
  assert.match(html, /data-accessible-tooltip title="[^"]*floating-point/);
});

void test("selects zero-valued enums without selecting unset bit flags", () => {
  const states = chips(renderFlags(243, 0));
  assert.equal(states.get("EF_RISCV_FLOAT_ABI_SOFT"), "sel");
  assert.equal(states.get("EF_RISCV_RVC"), "dim");
  assert.equal(states.get("EF_RISCV_RVE"), "dim");
  assert.equal(states.get("EF_RISCV_TSO"), "dim");
});

// GNU readelf decode_ARM_machine_flags distinguishes EABI versions 0,1,2,3,4,5.
void test("ARM EABI5 shows only the applicable flags and all EABI choices", () => {
  const states = chips(renderFlags(40, 0x05800400));
  assert.equal(states.get("EF_ARM_EABI_VER5"), "sel");
  assert.equal(states.get("EF_ARM_EABI_VER1"), "dim");
  assert.equal(states.get("EF_ARM_EABI_VER4"), "dim");
  assert.equal(states.get("EF_ARM_ABI_FLOAT_HARD"), "sel");
  assert.equal(states.get("EF_ARM_ABI_FLOAT_SOFT"), "dim");
  assert.equal(states.get("EF_ARM_BE8"), "sel");
  assert.equal(states.get("EF_ARM_LE8"), "dim");
  assert.equal(states.has("EF_ARM_INTERWORK"), false);
  assert.equal(states.has("EF_ARM_VFP_FLOAT"), false);
});

void test("ARM legacy bits retain their legacy meanings", () => {
  const states = chips(renderFlags(40, 0x404));
  assert.equal(states.get("EF_ARM_EABI_UNKNOWN"), "sel");
  assert.equal(states.get("EF_ARM_INTERWORK"), "sel");
  assert.equal(states.get("EF_ARM_VFP_FLOAT"), "sel");
  assert.equal(states.has("EF_ARM_ABI_FLOAT_HARD"), false);
});

void test("ARM EABI1 and EABI2 do not label symbol-order bits as interworking", () => {
  assert.equal(chips(renderFlags(40, 0x01000004)).get("EF_ARM_SYMSARESORTED"), "sel");
  const states = chips(renderFlags(40, 0x02000018));
  assert.equal(states.get("EF_ARM_DYNSYMSUSESEGIDX"), "sel");
  assert.equal(states.get("EF_ARM_MAPSYMSFIRST"), "sel");
  assert.equal(states.has("EF_ARM_APCS_26"), false);
});

void test("ARM EABI3, EABI4 and future ABIs preserve unrecognized bits", () => {
  assert.match(renderFlags(40, 0x03000004), /UNKNOWN_BITS_0x00000004/);
  assert.equal(chips(renderFlags(40, 0x04400000)).get("EF_ARM_LE8"), "sel");
  assert.match(renderFlags(40, 0x06000004), /Unknown ARM EABI version: 0x06000000/);
});

void test("MIPS high-bit ISA and composite ABI values use masked equality", () => {
  const states = chips(renderFlags(8, 0xa0003003));
  assert.equal(states.get("EF_MIPS_ARCH_64R6"), "sel");
  assert.equal(states.get("EF_MIPS_ARCH_64R2"), "dim");
  assert.equal(states.get("EF_MIPS_ABI_EABI32"), "sel");
  assert.equal(states.get("EF_MIPS_ABI_O32"), "dim");
  assert.equal(states.get("EF_MIPS_ABI_O64"), "dim");
  assert.equal(states.get("EF_MIPS_NOREORDER"), "sel");
  assert.equal(states.get("EF_MIPS_PIC"), "sel");
  assert.deepEqual(chips(renderFlags(10, 0xa0003003)), states);
});

void test("preserves unknown bits, including bit 31, alongside known flags", () => {
  assert.match(renderFlags(243, 0x80000001), /UNKNOWN_BITS_0x80000000/);
  assert.equal(chips(renderFlags(243, 0x80000001)).get("EF_RISCV_RVC"), "sel");
});

void test("unknown architectures and architectures without flags keep the raw word", () => {
  assert.match(renderFlags(0xffff, 0xdeadbeef), /0xdeadbeef/);
  assert.match(renderFlags(0xffff, 0xdeadbeef), /UNKNOWN_BITS_0xdeadbeef/);
  assert.match(renderFlags(62, 0), /No processor-specific flag definitions/);
  assert.match(renderFlags(183, 0), /0x00000000/);
  assert.equal(chips(renderFlags(62, 0)).size, 0);
});

void test("unknown enumerated values remain visible even when their masked value is zero", () => {
  assert.match(renderFlags(21, 3), /Unknown PowerPC64 ABI: 0x00000003/);
  assert.match(renderFlags(258, 0), /Unknown Floating-point ABI: 0x00000000/);
  assert.doesNotMatch(renderFlags(21, 3), /UNKNOWN_BITS/);
  assert.doesNotMatch(renderFlags(21, 2), /Unknown PowerPC64 ABI/);
  assert.doesNotMatch(renderFlags(243, 0), /Unknown |UNKNOWN_BITS/);
});

// llvm/BinaryFormat/ELF.h: HSA ABI versions 0/1/2/3/4 encode V2/V3/V4/V5/V6.
void test("AMDGPU HSA V2 feature bits are not decoded as a processor", () => {
  const states = chips(renderFlags(224, 3, 64, 0));
  assert.equal(states.get("EF_AMDGPU_FEATURE_XNACK_V2"), "sel");
  assert.equal(states.get("EF_AMDGPU_FEATURE_TRAP_HANDLER_V2"), "sel");
  assert.equal(states.has("EF_AMDGPU_MACH_AMDGCN_GFX600"), false);
});

void test("AMDGPU V3 bits and V4 masked feature states stay distinct", () => {
  assert.equal(chips(renderFlags(224, 0x120, 64, 1))
    .get("EF_AMDGPU_FEATURE_XNACK_V3"), "sel");
  const states = chips(renderFlags(224, 0x320, 64, 2));
  assert.equal(states.get("EF_AMDGPU_MACH_AMDGCN_GFX600"), "sel");
  assert.equal(states.get("EF_AMDGPU_FEATURE_XNACK_ON_V4"), "sel");
  assert.equal(states.get("EF_AMDGPU_FEATURE_XNACK_OFF_V4"), "dim");
  assert.equal(states.get("EF_AMDGPU_FEATURE_SRAMECC_UNSUPPORTED_V4"), "sel");
  assert.equal(states.has("EF_AMDGPU_FEATURE_XNACK_V3"), false);
});

void test("AMDGPU generic version is decoded only for HSA V6", () => {
  assert.match(renderFlags(224, 0x01000020, 64, 4), /Generic target version: 0x01000000/);
  assert.match(renderFlags(224, 0x01000020, 64, 3), /UNKNOWN_BITS_0x01000000/);
  assert.match(renderFlags(224, 0x20, 64, 5), /No processor-specific flag definitions/);
  assert.equal(chips(renderFlags(224, 0x120, 65, 0))
    .get("EF_AMDGPU_FEATURE_XNACK_V3"), "sel");
  assert.match(renderFlags(224, 0x20, 67, 0), /No processor-specific flag definitions/);
  assert.equal(chips(renderFlags(224, 0x20, 64, 4))
    .get("EF_AMDGPU_MACH_AMDGCN_GFX600"), "sel");
});

void test("numeric fields expose their raw bit position and accessible explanations", () => {
  const html = renderFlags(247, 5);
  assert.match(html, /<code>0x00000005<\/code>/);
  assert.match(html, /<div class="optionsRow">/);
  assert.match(html, /title="BPF CPU version; mask 0x0000000f\. Numeric field;/);
  assert.equal(chips(html).get("BPF CPU version: 0x00000005"), "sel");
  assert.doesNotMatch(html, /Unknown/);
  assert.ok(html.endsWith("</div>"));
});

void test("unknown enum choices and unknown bits include explanatory help", () => {
  assert.match(renderFlags(21, 3), /title="PowerPC64 ABI; mask 0x00000003\. This encoded value/);
  assert.match(renderFlags(62, 1), /data-accessible-tooltip title="Set bits with no known meaning/);
  assert.match(renderFlags(62, 0), /<div class="smallNote">No processor-specific flag definitions/);
});

void test("SPARC32PLUS-only flag is not interpreted for SPARCV9", () => {
  assert.equal(chips(renderFlags(18, 0x100)).get("EF_SPARC_32PLUS"), "sel");
  assert.match(renderFlags(43, 0x100), /UNKNOWN_BITS_0x00000100/);
  assert.equal(chips(renderFlags(43, 0x100)).has("EF_SPARC_32PLUS"), false);
});

void test("NDS32 shared PIC/ZOL bit preserves the upstream ambiguity", () => {
  const html = renderFlags(167, 0x14000012);
  assert.equal(chips(html).get("E_NDS32_HAS_PIC / E_NDS32_HAS_ZOL"), "sel");
  assert.match(html, /The ELF header alone does not distinguish these meanings/);
});

void test("CUDA V1 and V2 use different SM bit positions", () => {
  assert.equal(chips(renderFlags(190, 0x550, 51, 7)).get("EF_CUDA_SM80"), "sel");
  const states = chips(renderFlags(190, 0x6408, 51, 8));
  assert.equal(states.get("EF_CUDA_SM100"), "sel");
  assert.equal(states.get("EF_CUDA_ACCELERATORS"), "sel");
  assert.equal(states.has("EF_CUDA_64BIT_ADDRESS"), false);
  assert.match(renderFlags(190, 0x6408, 51, 9), /UNKNOWN_BITS_0x00006408/);
});

void test("IA-64 OS-specific flags distinguish Unix and OpenVMS", () => {
  assert.equal(chips(renderFlags(50, 0x11, 0)).get("EF_IA_64_TRAPNIL"), "sel");
  const states = chips(renderFlags(50, 0x11, 13));
  assert.equal(states.get("EF_IA_64_VMS_COMCOD_WARNING"), "sel");
  assert.equal(states.get("EF_IA_64_ABI64"), "sel");
  assert.equal(states.has("EF_IA_64_TRAPNIL"), false);
});

// Independent numeric examples from GNU include/elf/*.h and LLVM ELF.h.
for (const [machine, flags, name] of [
  [20, 0x80000000, "EF_PPC_EMB"], [21, 2, "ELFv2"],
  [43, 2, "EF_SPARCV9_RMO"], [258, 0x43, "EF_LOONGARCH_ABI_DOUBLE_FLOAT"],
  [83, 0xe4, "EF_AVR_ARCH_AVRTINY"], [42, 0x8009, "EF_SH4"],
  [105, 45, "EF_MSP430_MACH_MSP430X"], [15, 0x214, "EFA_PARISC_2_0"],
  [94, 0x100, "EF_XTENSA_XT_INSN"], [220, 0x84, "EF_Z80_MACH_EZ80_ADL"],
  [4, 0x23, "EF_M68K_CF_ISA_A_PLUS"], [87, 0x60000000, "E_V850E3V5_ARCH"],
  [250, 0x600000, "NFP-6xxx"], [252, 0x20000010, "EF_CSKY_802"]
] as const) {
  void test(`architecture ${machine} selects ${name}`, () => {
    assert.equal(chips(renderFlags(machine, flags)).get(name), "sel");
  });
}

void test("ELF header UI includes the raw flags and accessible help", async () => {
  const elf = await readElfFileHeader(createElfFile());
  assert.ok(elf);
  elf.header.machine = 243;
  elf.header.flags = 5;
  const out: string[] = [];
  renderHeader(elf, out);
  const html = out.join("");
  assert.match(html, />Flags \(e_flags\)<\/dt>/);
  assert.match(html, /0x00000005/);
  assert.equal(chips(html).get("EF_RISCV_FLOAT_ABI_DOUBLE"), "sel");
});
