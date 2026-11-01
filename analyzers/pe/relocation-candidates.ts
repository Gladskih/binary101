import { DEFAULT_FILE_READ_WINDOW_BYTES } from "../file-range-reader.js";
import { NATIVE_AOT_HEADER_SIZE } from "../native-aot/format.js";
import { COMPLETE_OBJECT_LOCATOR_SIZE, IMAGE_POINTER_SIZE } from "./msvc-rtti/layout.js";
import { readMsvcRttiCandidate } from "./msvc-rtti/discovery.js";
import type { PeRelocationDiscovery } from "./relocation-discovery-state.js";

interface PointerReadWindow { offset: number; view: DataView }

const loadSourceWindow = (
  state: PeRelocationDiscovery, window: PointerReadWindow, offset: number, needed: number
): Promise<void> | undefined => {
  if (offset >= window.offset && offset + needed <= window.offset + window.view.byteLength) return;
  return state.reader.read(offset,
    Math.min(DEFAULT_FILE_READ_WINDOW_BYTES, state.reader.size - offset)).then(view => {
    window.offset = offset;
    window.view = view;
  });
};

const readTarget = (
  state: PeRelocationDiscovery, window: PointerReadWindow, offset: number, needed: number
): number | null => {
  const relative = offset - window.offset;
  if (relative + needed > window.view.byteLength) {
    throw new Error("Truncated relocation pointer");
  }
  return state.nativeImage.preferredVaToRva(state.nativeImage.pointerSize === 8
    ? window.view.getBigUint64(relative, true) : BigInt(window.view.getUint32(relative, true)));
};

const collectNativeCandidate = (
  state: PeRelocationDiscovery, site: number, target: number
): void => {
  if (state.nativeImage.isDataRange(
    target, NATIVE_AOT_HEADER_SIZE, state.nativeImage.pointerSize
  )) state.nativeCandidates.set(site, target);
};

const collectMsvcCandidate = (
  state: PeRelocationDiscovery, site: number, target: number, view: DataView, offset: number
): void => {
  const image = state.msvcImage;
  if (!image || !state.msvcSites.has(site + IMAGE_POINTER_SIZE)) return;
  if (!image.isDataRange(target, COMPLETE_OBJECT_LOCATOR_SIZE, 4)) return;
  if (!image.isDataRange(site, 2 * IMAGE_POINTER_SIZE, IMAGE_POINTER_SIZE)) {
    // Adjacent RVAs can cross separately mapped sections; preserve their sparse reads.
    state.boundarySites.push(site);
    return;
  }
  const firstFunctionTargetRva = image.preferredVaToRva(view.getBigUint64(offset + IMAGE_POINTER_SIZE, true));
  if (firstFunctionTargetRva === null || !image.isExecutableRva(firstFunctionTargetRva)) return;
  state.msvcCandidates.push({ locatorSlotRva: site, locatorRva: target, firstFunctionTargetRva });
};

const readBoundaryCandidates = async (state: PeRelocationDiscovery): Promise<void> => {
  if (!state.msvcImage) return;
  for (const site of state.boundarySites) {
    const candidate = await readMsvcRttiCandidate(state.msvcImage, state.msvcSites, site);
    if (candidate) state.msvcCandidates.push(candidate);
  }
};

export const collectPeRelocationCandidates = async (state: PeRelocationDiscovery): Promise<void> => {
  const width = state.nativeImage.pointerSize;
  const window: PointerReadWindow = { offset: -1, view: new DataView(new ArrayBuffer(0)) };
  // Profiling msedge.dll: one source pass followed by ordered candidate checks
  // reduced discovery from 6.86 s to 1.55 s. Keep this window and mutation local.
  for (const site of state.sites) {
    state.itaniumImage.relocations.add(site);
    if (!state.nativeImage.isDataRange(site, width, width)) continue;
    const offset = state.itaniumImage.readOrder(site);
    const needed = state.msvcImage?.isDataRange(site, 2 * IMAGE_POINTER_SIZE, IMAGE_POINTER_SIZE)
      ? 2 * IMAGE_POINTER_SIZE : width;
    const pending = loadSourceWindow(state, window, offset, needed);
    if (pending) await pending;
    const target = readTarget(state, window, offset, needed);
    if (target === null) continue;
    state.itaniumImage.pointers.set(site, target);
    collectNativeCandidate(state, site, target);
    collectMsvcCandidate(state, site, target, window.view, offset - window.offset);
  }
  await readBoundaryCandidates(state);
  state.msvcCandidates.sort((left, right) =>
    state.itaniumImage.readOrder(left.locatorRva) - state.itaniumImage.readOrder(right.locatorRva));
};
