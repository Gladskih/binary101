import type { CodeViewVariableLocation } from "../../analyzers/pe/debug/codeview-local-types.js";

// CV_LVARFLAGS / FRAMEPROCSYM::flags and ExpandEncodedBasePointerReg.
// https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h#L3068
const LOCAL_FLAGS = [[0, "parameter"], [1, "address taken"], [2, "compiler generated"], [3, "split aggregate"],
  [4, "aggregate member"], [5, "aliased"], [6, "alias"], [7, "return value"], [8, "optimized out"],
  [9, "enregistered global"], [10, "enregistered static"]] as const;
const FRAME_FLAGS = [[0, "alloca"], [1, "setjmp"], [2, "longjmp"], [3, "inline assembly"],
  [4, "exception states"], [5, "declared inline"], [6, "SEH"], [7, "naked"], [8, "GS checks"],
  [9, "asynchronous EH"], [10, "GS without stack ordering"], [11, "inlined"], [12, "strict GS"],
  [13, "safe buffers"], [18, "PGO"], [19, "valid profile counts"], [20, "optimized for speed"],
  [21, "CFG checks"], [22, "CFW checks"]] as const;

const flagsText = (flags: number, names: readonly (readonly [number, string])[], unknown: number): string => {
  const parts = names.filter(([bit]) => flags & 2 ** bit).map(([, name]) => name);
  if (unknown) parts.push(`unknown bits 0x${unknown.toString(16)}`);
  return parts.join(", ") || "none";
};

export const codeViewLocalFlags = (flags: number | undefined): string => flags === undefined
  ? "not stored" : flagsText(flags, LOCAL_FLAGS, flags & 0xf800);
export const codeViewFrameFlags = (flags: number): string => flagsText(flags, FRAME_FLAGS, (flags & 0xff800000) >>> 0);

export const codeViewFrameBase = (encoded: number, machine: number | undefined): string => {
  const registers = machine === 0x8664 ? ["none", "RSP", "RBP", "R13"]
    : machine === 0x14c ? ["none", "virtual frame", "EBP", "EBX"]
      : machine === 0x1c4 ? ["none", "SP", "R7", "reserved"] : undefined;
  return registers?.[encoded] ?? `encoded base ${encoded} (architecture mapping unavailable)`;
};

// CodeView register IDs are architecture-specific; never borrow another CPU's names.
// https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvconst.h
const intelRegister = (register: number, machine: number | undefined): string | undefined => {
  if (machine === 0x8664 && register >= 328 && register <= 343) {
    return ["RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP",
      "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"][register - 328]!;
  }
  if ([0x14c, 0x8664].includes(machine ?? 0) && register >= 17 && register <= 24) {
    return ["EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI"][register - 17]!;
  }
  return undefined;
};

const armRegister = (register: number, machine: number | undefined): string | undefined => {
  if (machine !== 0x1c4 || register < 10 || register > 25) return undefined;
  return register <= 22 ? `R${register - 10}` : ["SP", "LR", "PC"][register - 23]!;
};

export const codeViewLocalRegister = (register: number, machine: number | undefined): string =>
  intelRegister(register, machine) ?? armRegister(register, machine) ?? `CodeView register #${register}`;

// CV_HLSLREG_e is a separate namespace from architecture-specific CV_HREG_e.
// https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvconst.h#L3663
const SHADER_REGISTERS = ["temporary", "input", "output", "indexable temporary", "32-bit immediate",
  "64-bit immediate", "sampler", "resource", "constant buffer", "immediate constant buffer", "label",
  "input primitive ID", "output depth", "null", "rasterizer", "output coverage mask", "stream", "function body",
  "function table", "interface", "function input", "function output", "output control point ID",
  "input fork instance ID", "input join instance ID", "input control point", "output control point",
  "input patch constant", "input domain point", "this pointer", "unordered access view", "thread group shared memory",
  "input thread ID", "input thread group ID", "input thread ID in group", "input coverage mask",
  "flattened input thread ID in group", "input geometry shader instance ID", "output depth greater or equal",
  "output depth less or equal", "cycle counter"];

const shaderPlacement = (location: Extract<CodeViewVariableLocation, { kind: "shaderRegister" }>): string => {
  const properties = [`HLSL ${SHADER_REGISTERS[location.registerType] ?? "unknown"} register type #${location.registerType}`,
    `memory space #${(location.attributes >>> 3) & 0xf}`,
    location.registerOffsets === undefined ? `register offsets unavailable (${location.attributes & 3} dimensions)`
      : `register offsets [${location.registerOffsets.join(", ")}]`];
  if (location.attributes & 4) properties.push("spilled member");
  if (location.attributes & 0xff80) properties.push(`unknown attributes 0x${(location.attributes & 0xff80).toString(16)}`);
  return properties.join("; ");
};

const offsetPlacement = (location: Extract<CodeViewVariableLocation,
  { kind: "registerOffset" | "registerRelative" | "frameRelative" }>, machine: number | undefined): string => {
  if (location.kind === "registerOffset") {
    return `${codeViewLocalRegister(location.register, machine)} + stored unsigned offset ${location.offset}`;
  }
  const base = location.kind === "frameRelative" ? "frame base" : codeViewLocalRegister(location.register, machine);
  return `${base}${location.offset < 0 ? " - " : " + "}${Math.abs(location.offset)}`;
};

export const codeViewLocalPlacement = (location: CodeViewVariableLocation, machine: number | undefined): string => {
  switch (location.kind) {
    case "program": return `DIA program #${location.program} (not evaluated)`;
    case "register": return codeViewLocalRegister(location.register, machine);
    case "registers": return location.registers.length
      ? `${location.registers.map(register => codeViewLocalRegister(register, machine)).join(", ")} (most significant first)`
      : "empty register list";
    case "slot": return `IL slot #${location.slot}`;
    case "groupShared": return `DPC groupshared slot #${location.slot} + byte offset ${location.offset}`;
    case "shaderRegister": return shaderPlacement(location);
    default: return offsetPlacement(location, machine);
  }
};
