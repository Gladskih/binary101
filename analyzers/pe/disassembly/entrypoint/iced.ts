"use strict";

import {
  isIcedX86Module,
  type IcedInstructionObject,
  type IcedX86Module
} from "../../../x86/disassembly-iced.js";

/**
 * iced-x86 `Instruction` object after `Decoder.decodeOut()` has populated it.
 *
 * It intentionally keeps iced's accessor methods (`opKind`, `opRegister`,
 * `immediate`) because those are part of the runtime API we adapt from. It is
 * not a plain parsed instruction result returned by Binary101.
 */
export type { IcedInstructionObject } from "../../../x86/disassembly-iced.js";

/** Minimal iced-x86 formatter API needed by the entrypoint preview. */
export type IcedFormatter = { format(instruction: IcedInstructionObject): string; free(): void };

/** iced-x86 module shape required specifically by entrypoint disassembly. */
export type IcedModule = IcedX86Module & {
  Formatter: new (syntax: number) => IcedFormatter;
  FormatterSyntax: { Nasm: number };
  MemorySize: Record<string, number> & Record<number, string | undefined>;
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null;

export const isIcedModule = (value: unknown): value is IcedModule => {
  if (!isRecord(value) || !isIcedX86Module(value)) return false;
  const module = value as IcedX86Module & Record<string, unknown>;
  const formatterSyntax = module["FormatterSyntax"];
  const memorySize = module["MemorySize"];
  return (
    isRecord(formatterSyntax) &&
    isRecord(memorySize) &&
    typeof memorySize["UInt32"] === "number" &&
    typeof formatterSyntax["Nasm"] === "number" &&
    typeof module["Formatter"] === "function"
  );
};
