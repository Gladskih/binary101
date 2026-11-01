import type { FileRangeReader } from "../file-range-reader.js";
import { discoverItaniumRtti } from "../itanium-rtti/discovery.js";
import { decodeItaniumRttiTypeNames } from "../itanium-rtti/type-name.js";
import { analyzePeItaniumRtti } from "./itanium-rtti.js";
import { analyzePeMsvcRtti, msvcRttiReadFailure } from "./msvc-rtti/index.js";
import { discoverMsvcRttiCandidates } from "./msvc-rtti/discovery.js";
import { createMsvcRttiGraphParser } from "./msvc-rtti/graph-parser.js";
import { analyzePeNativeAotMetadata } from "./native-aot-metadata.js";
import { createPeRelocationDiscovery, type PeRelocationDiscovery } from "./relocation-discovery-state.js";
import { collectPeRelocationCandidates } from "./relocation-candidates.js";
import { analyzePeNativeAotCandidates } from "./relocation-native-aot.js";
import type { PeBaseRelocationResult } from "./directories/reloc.js";
import type { PeWindowsCore } from "./types.js";

const readMsvc = async (state: PeRelocationDiscovery) => {
  if (!state.msvcImage) return null;
  try {
    return await discoverMsvcRttiCandidates(state.msvcImage, state.msvcSites,
      createMsvcRttiGraphParser(state.msvcImage), state.msvcCandidates);
  } catch (error) {
    return msvcRttiReadFailure(error);
  }
};

const readItanium = async (state: PeRelocationDiscovery) => {
  try {
    const result = await discoverItaniumRtti(state.itaniumImage);
    if (result) await decodeItaniumRttiTypeNames(result);
    return result;
  } catch {
    return { types: [], warnings: ["Itanium RTTI analysis could not read file data."] };
  }
};

const readIndependent = async (
  reader: FileRangeReader, core: PeWindowsCore, relocations: PeBaseRelocationResult | null
) => ({
  nativeAotMetadata: await analyzePeNativeAotMetadata(reader, core, relocations),
  msvcRtti: await analyzePeMsvcRtti(reader, core, relocations),
  itaniumRtti: await analyzePeItaniumRtti(reader, core, relocations)
});

export const analyzePeRelocationStructures = async (
  reader: FileRangeReader, core: PeWindowsCore, relocations: PeBaseRelocationResult | null
) => {
  const state = createPeRelocationDiscovery(reader, core, relocations);
  if (!state) return readIndependent(reader, core, relocations);
  try {
    await collectPeRelocationCandidates(state);
    return { nativeAotMetadata: await analyzePeNativeAotCandidates(state, core),
      msvcRtti: await readMsvc(state), itaniumRtti: await readItanium(state) };
  } catch {
    // A failed shared analysis must preserve each analyzer's independent result
    // and diagnostics. Only this exceptional path retries the original readers.
    return readIndependent(reader, core, relocations);
  }
};
