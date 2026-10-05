import {
  IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64,
  IMAGE_FILE_MACHINE_ARMNT, IMAGE_FILE_MACHINE_I386
} from "../../coff/machine.js";
import { getCanonicalPeMachine } from "../machine.js";

// ReadyToRunReader.CalculateRuntimeFunctionSize / EnsureImportSectionsImpl.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.Reflection.ReadyToRun/ReadyToRunReader.cs
const targetMachine = (machine: number | undefined): number | undefined =>
  machine === undefined ? undefined : getCanonicalPeMachine(machine);

export const readyToRunPointerSize = (machine: number | undefined): 4 | 8 | undefined => {
  const target = targetMachine(machine);
  if (target === IMAGE_FILE_MACHINE_I386 || target === IMAGE_FILE_MACHINE_ARMNT) return 4;
  // PE/COFF machine IDs for LoongArch64 and RISC-V 64 are 0x6264 and 0x5064.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#machine-types
  return target === IMAGE_FILE_MACHINE_AMD64 || target === IMAGE_FILE_MACHINE_ARM64 ||
    target === 0x6264 || target === 0x5064 ? 8 : undefined;
};

export const readyToRunRuntimeFunctionSize = (machine: number | undefined): 8 | 12 | undefined => {
  if (targetMachine(machine) === IMAGE_FILE_MACHINE_AMD64) return 12;
  return readyToRunPointerSize(machine) === undefined ? undefined : 8;
};
