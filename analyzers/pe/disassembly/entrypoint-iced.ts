"use strict";

import { isIcedX86Module, type IcedX86Module } from "../../x86/disassembly-iced.js";

export type IcedInstruction = InstanceType<IcedX86Module["Instruction"]>;
export type IcedFormatter = { format(instruction: IcedInstruction): string; free(): void };
export type EntrypointIcedModule = IcedX86Module & {
  Formatter: new (syntax: number) => IcedFormatter;
  FormatterSyntax: { Nasm: number };
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null;

export const isEntrypointIcedModule = (value: unknown): value is EntrypointIcedModule => {
  if (!isRecord(value) || !isIcedX86Module(value)) return false;
  const module = value as IcedX86Module & Record<string, unknown>;
  const formatterSyntax = module["FormatterSyntax"];
  return (
    isRecord(formatterSyntax) &&
    typeof formatterSyntax["Nasm"] === "number" &&
    typeof module["Formatter"] === "function"
  );
};
