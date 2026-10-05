import type { NativeAotMetadata } from "./format.js";

const uniqueGroup = (source: string, addresses: (number | null)[]) => {
  const rvas = [...new Set(addresses.filter(address => address !== null))];
  return rvas.length ? [{ source, rvas }] : [];
};

export const collectNativeAotMapSeeds = (
  metadata: NativeAotMetadata
): { source: string; rvas: number[] }[] => {
  const invokes = metadata.invokeMap?.entries ?? [];
  return [
    ...uniqueGroup("NativeAOT invoke methods", invokes.map(entry => entry.entrypointRva)),
    ...uniqueGroup("NativeAOT invoke stubs", invokes.map(entry => entry.invokeStubRva)),
    ...uniqueGroup("NativeAOT stack-trace methods",
      (metadata.stackTraceMap?.entries ?? []).map(entry => entry.methodRva))
  ];
};
