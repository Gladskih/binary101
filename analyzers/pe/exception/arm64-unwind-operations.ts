import type { Arm64UnwindBody, Arm64UnwindOperation, Arm64UnwindSave } from "./arm64-unwind-types.js";

// Microsoft ARM64 exception handling, "Unwind codes". Operand bytes are big-endian.
// https://learn.microsoft.com/en-us/cpp/build/arm64-exception-handling#unwind-codes
// Independently implemented in LLVM ARMWinEHPrinter (including pre-index +1).
// https://github.com/llvm/llvm-project/blob/llvmorg-23.1.3/llvm/tools/llvm-readobj/ARMWinEHPrinter.cpp
const saved = (registers: string[], displacement: number,
  addressing: Arm64UnwindSave["addressing"]): Arm64UnwindSave =>
  ({ kind: "save", registers, displacement, addressing, unit: "bytes" });

const register = (bank: string, index: number): string => bank === "X" && index === 30 ? "LR" : `${bank}${index}`;
const pair = (bank: string, first: number): string[] => [register(bank, first), register(bank, first + 1)];
const allocation = (amount: number): Arm64UnwindBody => ({ kind: "allocate", amount, unit: "bytes" });

const smallOperation = (view: DataView): Arm64UnwindBody => {
  const byte = view.getUint8(0);
  if (byte < 0x20) return allocation((byte & 31) * 16);
  if (byte < 0x40) return saved(pair("X", 19), -(byte & 31) * 8, "preIndex");
  if (byte < 0x80) return saved(["X29", "LR"], (byte & 63) * 8, "offset");
  return saved(["X29", "LR"], -((byte & 63) + 1) * 8, "preIndex");
};

const generalSave = (view: DataView): Arm64UnwindBody => {
  const byte = view.getUint8(0), operand = view.getUint8(1);
  const first = 19 + (((byte & 3) << 8 | operand & 0xc0) >>> 6);
  if (byte < 0xcc) return saved(pair("X", first), (operand & 63) * 8, "offset");
  if (byte < 0xd0) return saved(pair("X", first), -((operand & 63) + 1) * 8, "preIndex");
  return saved([register("X", first)], (operand & 63) * 8, "offset");
};

const compactGeneralSave = (view: DataView): Arm64UnwindBody => {
  const byte = view.getUint8(0), operand = view.getUint8(1);
  if (byte < 0xd6) {
    const first = 19 + (((byte & 1) << 8 | operand & 0xe0) >>> 5);
    return saved([register("X", first)], -((operand & 31) + 1) * 8, "preIndex");
  }
  const first = 19 + 2 * (((byte & 1) << 8 | operand & 0xc0) >>> 6);
  return saved([register("X", first), "LR"], (operand & 63) * 8, "offset");
};

const floatingSave = (view: DataView): Arm64UnwindBody => {
  const byte = view.getUint8(0), operand = view.getUint8(1);
  if (byte === 0xde) return saved([`D${8 + (operand >>> 5)}`], -((operand & 31) + 1) * 8, "preIndex");
  const first = 8 + (((byte & 1) << 8 | operand & 0xc0) >>> 6);
  if (byte < 0xda) return saved(pair("D", first), (operand & 63) * 8, "offset");
  if (byte < 0xdc) return saved(pair("D", first), -((operand & 63) + 1) * 8, "preIndex");
  return saved([`D${first}`], (operand & 63) * 8, "offset");
};

const scalableSave = (first: number, second: number, issues: string[]): Arm64UnwindBody | null => {
  const index = first & 15;
  const displacement = ((first & 0x60) << 1) | second & 63;
  if ((first & 16) === 0) return { kind: "save", registers: [`Z${index + 8}`],
    displacement, addressing: "offset", unit: "vectorLengths" };
  if (index === 0) return saved(["VG", "SM"], displacement * 8, "offset");
  if (index < 4) {
    issues.push(`ARM64 save_preg has reserved predicate register P${index}.`);
    return null;
  }
  return { kind: "save", registers: [`P${index}`], displacement, addressing: "offset", unit: "predicateLengths" };
};

const anyDisplacement = (first: number, second: number): number => {
  const writeback = (first & 32) !== 0;
  const scale = (first & 0x60) !== 0 || (second >>> 6) === 2 ? 16 : 8;
  return ((second & 63) + Number(writeback)) * scale * (writeback ? -1 : 1);
};

const ordinaryAnySave = (first: number, second: number, issues: string[]): Arm64UnwindBody | null => {
  const bank = second >>> 6;
  const paired = (first & 0x40) !== 0;
  const writeback = (first & 0x20) !== 0;
  const index = first & 31;
  const maximum = (bank === 0 ? 30 : 31) - Number(paired);
  if (index > maximum) {
    issues.push("ARM64 save_any_reg exceeds its register bank.");
    return null;
  }
  const prefix = ["X", "D", "Q"][bank]!;
  return saved(paired ? pair(prefix, index) : [register(prefix, index)],
    anyDisplacement(first, second), writeback ? "preIndex" : "offset");
};

const anySave = (view: DataView, issues: string[]): Arm64UnwindBody | null => {
  const first = view.getUint8(1), second = view.getUint8(2);
  return second >>> 6 === 3 ? scalableSave(first, second, issues) : ordinaryAnySave(first, second, issues);
};

interface OpcodeEncoding {
  mask: number;
  value: number;
  length: number;
  name: string;
  read: (view: DataView, issues: string[]) => Arm64UnwindBody | null;
}

const marker = (): Arm64UnwindBody => ({ kind: "marker" });
const ENCODINGS: readonly OpcodeEncoding[] = [
  { mask: 0xe0, value: 0x00, length: 1, name: "alloc_s", read: smallOperation },
  { mask: 0xe0, value: 0x20, length: 1, name: "save_r19r20_x", read: smallOperation },
  { mask: 0xc0, value: 0x40, length: 1, name: "save_fplr", read: smallOperation },
  { mask: 0xc0, value: 0x80, length: 1, name: "save_fplr_x", read: smallOperation },
  { mask: 0xf8, value: 0xc0, length: 2, name: "alloc_m",
    read: view => allocation(((view.getUint8(0) & 7) * 256 + view.getUint8(1)) * 16) },
  { mask: 0xfc, value: 0xc8, length: 2, name: "save_regp", read: generalSave },
  { mask: 0xfc, value: 0xcc, length: 2, name: "save_regp_x", read: generalSave },
  { mask: 0xfc, value: 0xd0, length: 2, name: "save_reg", read: generalSave },
  { mask: 0xfe, value: 0xd4, length: 2, name: "save_reg_x", read: compactGeneralSave },
  { mask: 0xfe, value: 0xd6, length: 2, name: "save_lrpair", read: compactGeneralSave },
  { mask: 0xfe, value: 0xd8, length: 2, name: "save_fregp", read: floatingSave },
  { mask: 0xfe, value: 0xda, length: 2, name: "save_fregp_x", read: floatingSave },
  { mask: 0xfe, value: 0xdc, length: 2, name: "save_freg", read: floatingSave },
  { mask: 0xff, value: 0xde, length: 2, name: "save_freg_x", read: floatingSave },
  { mask: 0xff, value: 0xdf, length: 2, name: "alloc_z",
    read: view => ({ kind: "allocate", amount: view.getUint8(1), unit: "vectorLengths" }) },
  { mask: 0xff, value: 0xe0, length: 4, name: "alloc_l",
    read: view => allocation((view.getUint8(1) * 65536 + view.getUint16(2, false)) * 16) },
  { mask: 0xff, value: 0xe1, length: 1, name: "set_fp", read: () => ({ kind: "frame", displacement: 0 }) },
  { mask: 0xff, value: 0xe2, length: 2, name: "add_fp",
    read: view => ({ kind: "frame", displacement: view.getUint8(1) * 8 }) },
  { mask: 0xff, value: 0xe3, length: 1, name: "nop", read: marker },
  { mask: 0xff, value: 0xe4, length: 1, name: "end", read: marker },
  { mask: 0xff, value: 0xe5, length: 1, name: "end_c", read: marker },
  { mask: 0xff, value: 0xe6, length: 1, name: "save_next", read: marker },
  { mask: 0xff, value: 0xe7, length: 3, name: "save_any_reg", read: anySave },
  { mask: 0xff, value: 0xe8, length: 1, name: "trap_frame", read: marker },
  { mask: 0xff, value: 0xe9, length: 1, name: "machine_frame", read: marker },
  { mask: 0xff, value: 0xea, length: 1, name: "context", read: marker },
  { mask: 0xff, value: 0xeb, length: 1, name: "ec_context", read: marker },
  { mask: 0xff, value: 0xec, length: 1, name: "clear_unwound_to_call", read: marker },
  { mask: 0xff, value: 0xfc, length: 1, name: "pac_sign_lr", read: marker }
];

const validSave = (body: Arm64UnwindBody, issues: string[]): boolean => {
  if (body.kind !== "save") return true;
  const invalid = body.registers.some(name => {
    const match = /^([XDQ])(\d+)$/.exec(name);
    return match != null && Number(match[2]) > (match[1] === "X" ? 30 : 31);
  });
  if (invalid) issues.push("ARM64 unwind save exceeds its register bank.");
  return !invalid;
};

const opcodeName = (name: string, body: Arm64UnwindBody): string => {
  if (name !== "save_any_reg" || body.kind !== "save") return name;
  if (body.unit === "vectorLengths") return "save_zreg";
  if (body.unit === "predicateLengths") return "save_preg";
  return body.registers[0] === "VG" ? "save_vg_sm" : name;
};

const readEncodedBody = (view: DataView, offset: number, encoding: OpcodeEncoding,
  issues: string[]): Arm64UnwindBody | null => {
  // E7 1yyyyyyy is a reserved two-byte encoding, not a truncated three-byte save.
  if (encoding.value === 0xe7 && offset + 2 <= view.byteLength && (view.getUint8(offset + 1) & 0x80) !== 0) {
    issues.push("ARM64 save_any_reg has its reserved high bit set.");
    return null;
  }
  if (offset + encoding.length > view.byteLength) {
    issues.push(`ARM64 unwind opcode ${view.getUint8(offset)} at byte ${offset} has truncated operands.`);
    return null;
  }
  return encoding.read(new DataView(view.buffer, view.byteOffset + offset, encoding.length), issues);
};

export const decodeArm64UnwindOperation = (view: DataView, offset: number,
  issues: string[]): Arm64UnwindOperation | null => {
  if (!Number.isInteger(offset) || offset < 0 || offset >= view.byteLength) {
    issues.push("ARM64 unwind operation offset is out of bounds.");
    return null;
  }
  const byte = view.getUint8(offset);
  const encoding = ENCODINGS.find(value => (byte & value.mask) === value.value);
  if (!encoding) {
    issues.push(`ARM64 unwind opcode ${byte} at byte ${offset} is unknown or reserved.`);
    return null;
  }
  const body = readEncodedBody(view, offset, encoding, issues);
  if (!body || !validSave(body, issues)) return null;
  return { opcode: opcodeName(encoding.name, body), offset, byteLength: encoding.length, ...body };
};
