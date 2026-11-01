import {
  parseNativeAotRuntimeHeader, readNativeAotHeaderReflection, readNativeAotMetadata,
  type NativeAotReadyToRunHeader
} from "../native-aot/ready-to-run.js";
import type { NativeAotMetadata } from "../native-aot/format.js";
import { readPeNativeAotGc } from "./native-aot-gc.js";
import type { PeRelocationDiscovery } from "./relocation-discovery-state.js";
import type { PeWindowsCore } from "./types.js";

const readHeaders = async (state: PeRelocationDiscovery) => {
  const headers = new Map<number, NativeAotReadyToRunHeader>();
  const failures = new Set<number>();
  for (const target of [...new Set(state.nativeCandidates.values())].sort((left, right) =>
    state.itaniumImage.readOrder(left) - state.itaniumImage.readOrder(right))) {
    try {
      const header = await parseNativeAotRuntimeHeader(state.nativeImage, state.nativeSites, target);
      if (header) headers.set(target, header);
    } catch {
      failures.add(target);
    }
  }
  return { headers, failures };
};

export const analyzePeNativeAotCandidates = async (
  state: PeRelocationDiscovery, core: PeWindowsCore
): Promise<NativeAotMetadata | null> => {
  const { headers, failures } = await readHeaders(state);
  if (!headers.size) return null;
  // Preserve the first result/failure in the original relocation order, regardless
  // of the physical order used to validate candidate headers and their graphs.
  for (const site of state.nativeSites) {
    const target = state.nativeCandidates.get(site);
    if (target === undefined) continue;
    if (failures.has(target)) return null;
    const header = headers.get(target);
    if (!header) continue;
    const metadata = await readNativeAotMetadata(state.nativeImage, site,
      await readNativeAotHeaderReflection(state.nativeImage, header));
    await readPeNativeAotGc(state.reader, core, metadata);
    return metadata;
  }
  return null;
};
