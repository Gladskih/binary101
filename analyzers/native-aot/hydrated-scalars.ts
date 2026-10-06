import type { NativeAotHydratedRun } from "./dehydrated-stream-types.js";
import type { NativeAotVirtualImage } from "./virtual-image-types.js";

export const findNativeAotHydratedRun = (
  runs: NativeAotHydratedRun[], address: number
): NativeAotHydratedRun | undefined => {
  let left = 0;
  let right = runs.length;
  while (left < right) {
    const middle = Math.floor((left + right) / 2);
    if (runs[middle]!.rva <= address) left = middle + 1;
    else right = middle;
  }
  const run = runs[left - 1];
  return run && address < run.rva + run.size ? run : undefined;
};

const readByte = async (image: NativeAotVirtualImage,
  run: NativeAotHydratedRun | undefined, address: number): Promise<number> => {
  if (run?.kind === "zero") return 0;
  if (run && run.kind !== "copy") throw new Error("NativeAOT scalar overlaps a dehydrated pointer.");
  const view = await image.readData(run ? run.sourceRva + address - run.rva : address, 1, 1);
  if (!view || view.byteLength !== 1) throw new Error("NativeAOT scalar is truncated or unreadable.");
  return view.getUint8(0);
};

export const readNativeAotHydratedUnsigned = async (
  image: NativeAotVirtualImage, runs: NativeAotHydratedRun[], address: number, size: 2 | 4
): Promise<number> => {
  if (![2, 4].includes(size) || !Number.isSafeInteger(address) || address < 0 ||
    !image.isMappedRange(address, size)) throw new Error("NativeAOT scalar has an invalid mapped range.");
  // Scalars can span Copy/ZeroFill command boundaries; pointer commands are separate typed fields.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Runtime/DehydratedData.cs
  let value = 0;
  for (let offset = 0; offset < size; offset++) {
    value += await readByte(image, findNativeAotHydratedRun(runs, address + offset), address + offset) *
      2 ** (offset * 8);
  }
  return value;
};
