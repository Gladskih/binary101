// ARMEmitter.EmitMOV(symbol): MOVW/MOVT + ADD PC. RelocationHelper subtracts sourceRVA + 12.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.ReadyToRun/ObjectWriter/RelocationHelper.cs
const writePcRelativeCell = (view: DataView, offset: number, register: number, cell: number): void => {
  const delta = cell - (0x100 + offset + 12);
  for (let index = 0; index < 2; index++) {
    const immediate = (delta >>> (16 * index)) & 0xffff;
    view.setUint16(offset + index * 4, (index ? 0xf2c0 : 0xf240) |
      ((immediate & 0xf000) >>> 12) | ((immediate & 0x800) >>> 1), true);
    view.setUint16(offset + index * 4 + 2,
      (register << 8) | ((immediate & 0x700) << 4) | (immediate & 0xff), true);
  }
  view.setUint16(offset + 8, register <= 7 ? 0x4478 + register : 0x44f0 + register, true);
};

export const armEagerThunkCode = (cell = 0x3000): DataView => {
  const view = new DataView(new ArrayBuffer(16));
  writePcRelativeCell(view, 0, 12, cell);
  view.setUint16(10, 0xf8dc, true);
  view.setUint16(12, 0xc000, true);
  view.setUint16(14, 0x4760, true);
  return view;
};

export const armLazyThunkCode = (): DataView => {
  const view = new DataView(new ArrayBuffer(28));
  writePcRelativeCell(view, 0, 1, 0x2000);
  view.setUint16(10, 0x6809, true);
  writePcRelativeCell(view, 12, 12, 0x3000);
  view.setUint16(22, 0xf8dc, true);
  view.setUint16(24, 0xc000, true);
  view.setUint16(26, 0x4760, true);
  return view;
};

export const armDelayThunkCode = (index = 3): DataView => {
  const view = new DataView(new ArrayBuffer(40));
  view.setUint16(0, 0xf84d, true);
  view.setUint16(2, 0x4d04, true);
  view.setUint16(4, 0x2400 | index, true);
  view.setUint16(6, 0xf84d, true);
  view.setUint16(8, 0x4d04, true);
  writePcRelativeCell(view, 10, 4, 0x2000);
  view.setUint16(20, 0x6824, true);
  view.setUint16(22, 0xf84d, true);
  view.setUint16(24, 0x4d04, true);
  writePcRelativeCell(view, 26, 4, 0x3000);
  view.setUint16(36, 0x6824, true);
  view.setUint16(38, 0x4720, true);
  return view;
};

export const armAbsoluteThunkCode = (kind: "eager" | "lazy" | "delay-load family",
  helper = 0x403000, module = 0x402000): DataView => {
  const modern = { eager: armEagerThunkCode, lazy: armLazyThunkCode,
    "delay-load family": armDelayThunkCode }[kind]();
  const helperOffset = kind === "eager" ? 0 : kind === "lazy" ? 12 : 26;
  writePcRelativeCell(modern, helperOffset, kind === "delay-load family" ? 4 : 12,
    helper + 0x100 + helperOffset + 12);
  const removed = [helperOffset + 8, helperOffset + 9];
  if (kind !== "eager") {
    const moduleOffset = kind === "lazy" ? 0 : 10;
    writePcRelativeCell(modern, moduleOffset, kind === "lazy" ? 1 : 4,
      module + 0x100 + moduleOffset + 12);
    removed.push(moduleOffset + 8, moduleOffset + 9);
  }
  return new DataView(Uint8Array.from(new Uint8Array(modern.buffer)
    .filter((_byte, index) => !removed.includes(index))).buffer);
};
