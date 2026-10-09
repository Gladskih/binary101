import type { NativeAotHydratedRun } from "./dehydrated-stream-types.js";
import type { NativeAotVirtualImage } from "./virtual-image-types.js";
import { findNativeAotHydratedRun, readNativeAotHydratedUnsigned } from "./hydrated-scalars.js";

const validateAddress = (image: NativeAotVirtualImage, address: number): void => {
  if (!Number.isSafeInteger(address) || address < 0 || address % 4 ||
    !image.isMappedRange(address, 4)) throw new Error("NativeAOT relative pointer has an invalid mapped range.");
};

const relocationTarget = (run: NativeAotHydratedRun | undefined, address: number): number | undefined => {
  if (run?.kind === "pointer") throw new Error("NativeAOT hydrated field is not a relative pointer.");
  if (run?.kind === "relative") {
    if (address !== run.rva || run.size !== 4) {
      throw new Error("NativeAOT hydrated relocation is not a complete relative field.");
    }
    return run.target;
  }
  return undefined;
};

const storedTarget = async (image: NativeAotVirtualImage,
  runs: NativeAotHydratedRun[], address: number): Promise<number> => {
  // Copy stores the displacement for the hydrated destination, not for its compressed source.
  // Zero displacement points at the field itself (FollowRelativePointer), not address zero.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/nativeaot/Common/src/Internal/Runtime/MethodTable.cs
  const raw = await readNativeAotHydratedUnsigned(image, runs, address, 4);
  const target = address + (raw >= 0x80000000 ? raw - 0x100000000 : raw);
  if (!Number.isSafeInteger(target) || target < 0) throw new Error("NativeAOT relative pointer has an invalid target.");
  return target;
};

export const readNativeAotHydratedRelative = async (
  image: NativeAotVirtualImage, runs: NativeAotHydratedRun[], address: number
): Promise<number> => {
  validateAddress(image, address);
  return relocationTarget(findNativeAotHydratedRun(runs, address), address) ??
    await storedTarget(image, runs, address);
};
