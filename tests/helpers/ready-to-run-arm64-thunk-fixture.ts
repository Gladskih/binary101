// Target_ARM64-ImportThunk.cs and ARM64Emitter.cs, dotnet/runtime v10.0.0.
export const arm64ThunkCode = (prefix: number[] = [], helper = 0x140003000n, module = 0x140002000n): DataView => {
  const bytes = new Uint8Array(prefix.length * 4 + 20 + (prefix.length ? 8 : 0));
  const view = new DataView(bytes.buffer);
  prefix.forEach((word, index) => view.setUint32(index * 4, word, true));
  view.setUint32(prefix.length * 4, 0x5800006c, true);
  view.setUint32(prefix.length * 4 + 4, 0xf940018c, true);
  view.setUint32(prefix.length * 4 + 8, 0xd61f0180, true);
  view.setBigUint64(prefix.length * 4 + 12, helper, true);
  if (prefix.length) view.setBigUint64(prefix.length * 4 + 20, module, true);
  return view;
};
