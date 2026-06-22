"use strict";

import type {
  IcedInstructionObject,
  IcedModule
} from "../../analyzers/pe/disassembly/entrypoint/iced.js";
import { fixtureIced } from "./pe-entrypoint-emulation-fixture.js";

const copyInstruction = (
  destination: IcedInstructionObject,
  source: IcedInstructionObject
): void => {
  Object.setPrototypeOf(destination, Object.getPrototypeOf(source) as object | null);
  Object.assign(destination, source);
};

export const createScriptedIced = (
  instructions: readonly IcedInstructionObject[]
): IcedModule => {
  const byIp = new Map(instructions.map(item => [item.ip.toString(), item]));
  class ScriptedDecoder {
    ip = 0n;
    position = 0;
    constructor(
      _bitness: number,
      readonly data: Uint8Array
    ) {}
    get canDecode(): boolean {
      return this.position < this.data.length && byIp.has(this.ip.toString());
    }
    decodeOut(instruction: IcedInstructionObject): void {
      const decoded = byIp.get(this.ip.toString());
      if (!decoded) throw new Error(`No scripted instruction for ${this.ip.toString(16)}`);
      copyInstruction(instruction, decoded);
      this.position += decoded.length;
      this.ip = decoded.nextIP;
    }
    free(): void {}
  }
  return { ...fixtureIced, Decoder: ScriptedDecoder };
};
