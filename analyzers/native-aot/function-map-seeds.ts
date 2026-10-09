import type { NativeAotFunctionMap, NativeAotFunctionMaps } from "./function-map-types.js";
import { nativeAotSectionName } from "./format.js";

const codeFields = (map: NativeAotFunctionMap): (number | null)[] => {
  if (map.type === 301) return map.entries.flatMap(entry => [
    ...(entry.runtimeType?.slots ?? []).flatMap(slot => slot.kind === "method" ? [slot.rva] : []),
    entry.runtimeType?.tail?.finalizerRva ?? null,
    ...(entry.runtimeType?.tail?.sealedSlots ?? []).map(slot => slot.targetRva)
  ]);
  if (map.type === 316) return map.entries.flatMap(entry =>
    [entry.marshalRva, entry.unmarshalRva, entry.cleanupRva]);
  if (map.type === 317) return map.entries.flatMap(entry =>
    [entry.openStaticRva, entry.closedRva, entry.forwardCreationRva]);
  if (map.type === 321 || map.type === 322) return map.entries.flatMap(entry => [
    ...("entrypointRva" in entry ? [entry.entrypointRva] : []),
    entry.layout?.classConstructorRva ?? null,
    ...(entry.layout?.dictionaryMethods ?? []).map(method => method.entrypointRva)
  ]);
  return map.entries.map(entry => entry.entrypointRva);
};

export const collectNativeAotFunctionMapSeeds = (
  data: NativeAotFunctionMaps | undefined
): { source: string; rvas: number[] }[] => (data?.maps ?? []).flatMap(map => {
  const rvas = [...new Set(codeFields(map).filter(address => address !== null))];
  return rvas.length ? [{ source: `NativeAOT ${nativeAotSectionName(map.type)}`, rvas }] : [];
});
