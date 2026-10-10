import { NibbleReader } from "../../native-aot/nibble-reader.js";
import { getCanonicalPeMachine } from "../machine.js";
import type { ReadyToRunDebugVariable, ReadyToRunVariableLocation } from "./ready-to-run-debug-types.js";

// All VarLoc tags and operand ordering, including the reversed STK_REG operands.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/vm/debuginfostore.cpp
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/inc/cordebuginfo.h
const locations: Readonly<Record<number, (reader: NibbleReader,
  stackOffset: () => number) => ReadyToRunVariableLocation>> = {
  0: reader => ({ kind: "register", register: reader.unsigned() }),
  1: reader => ({ kind: "register-byref", register: reader.unsigned() }),
  2: reader => ({ kind: "fp-register", register: reader.unsigned() }),
  3: (reader, offset) => ({ kind: "stack", baseRegister: reader.unsigned(), offset: offset() }),
  4: (reader, offset) => ({ kind: "stack-byref", baseRegister: reader.unsigned(), offset: offset() }),
  5: reader => ({ kind: "register-pair", register1: reader.unsigned(), register2: reader.unsigned() }),
  6: (reader, offset) => ({ kind: "register-stack", register: reader.unsigned(),
    baseRegister: reader.unsigned(), offset: offset() }),
  7: (reader, offset) => ({ kind: "stack-register", offset: offset(),
    baseRegister: reader.unsigned(), register: reader.unsigned() }),
  8: (reader, offset) => ({ kind: "stack-pair", baseRegister: reader.unsigned(), offset: offset() }),
  9: reader => ({ kind: "fp-stack", index: reader.unsigned() }),
  10: reader => ({ kind: "varargs", offset: reader.unsigned() })
};

const readLocation = (reader: NibbleReader, machine: number | undefined): ReadyToRunVariableLocation => {
  const tag = reader.unsigned();
  if (!Object.hasOwn(locations, tag)) throw new Error(`Unknown debug variable location ${tag}.`);
  return locations[tag]!(reader, () => {
    if (machine === undefined) throw new Error("Stack variable needs the target machine.");
    return reader.signed() * (getCanonicalPeMachine(machine) === 0x14c ? 4 : 1);
  });
};

export const readDebugVariables = (bytes: Uint8Array, machine: number | undefined,
  warnings: Set<string>): ReadyToRunDebugVariable[] => {
  const variables: ReadyToRunDebugVariable[] = [];
  try {
    const reader = new NibbleReader(bytes);
    const count = reader.unsigned();
    for (let index = 0; index < count; index++) {
      const startOffset = reader.unsigned();
      const endOffset = startOffset + reader.unsigned();
      if (endOffset > 0xffffffff) throw new Error("Debug variable lifetime overflow.");
      const variableNumber = reader.unsigned() - 4;
      variables.push({ startOffset, endOffset, variableNumber, location: readLocation(reader, machine) });
    }
  } catch (error) { warnings.add(`Debug variables: ${(error as Error).message}`); }
  return variables;
};
