// GNU Binutils SFrame specifications 2.40, 2.44 and 2.46, §§2.2–2.4.
export const sframePayload = (version: number, little = true, count = 1) => {
  const descriptorSize = [0, 17, 20, 16][version]!;
  const descriptorStart = 32; // 28-byte header plus 4 auxiliary bytes.
  const rowStart = descriptorStart + descriptorSize * count;
  const attrSize = version === 3 ? 5 : 0;
  const rowSize = 6; // 16-bit PC offset, one info byte, three 8-bit offsets.
  const bytes = new Uint8Array(rowStart + count * (attrSize + rowSize));
  const view = new DataView(bytes.buffer);
  view.setUint16(0, 0xdee2, little);
  bytes.set([version, version === 1 ? 1 : 5, little ? 2 : 1, 0, 0, 4], 2);
  view.setUint32(8, count, little);
  view.setUint32(12, count, little);
  view.setUint32(16, bytes.length - rowStart, little);
  view.setUint32(24, rowStart - descriptorStart, little);
  for (let index = 0; index < count; index++) {
    const descriptor = descriptorStart + index * descriptorSize;
    const funcOffset = (version === 1 ? 0 : -descriptor) - 0x1000 + index * 32;
    const rowOffset = index * (attrSize + rowSize);
    const data = rowStart + rowOffset;
    if (version === 3) {
      view.setBigInt64(descriptor, BigInt(funcOffset), little);
      view.setUint32(descriptor + 8, 32, little);
      view.setUint32(descriptor + 12, rowOffset, little);
      view.setUint16(data, 1, little);
      bytes[data + 2] = 1; // FRE type ADDR2.
    } else {
      view.setInt32(descriptor, funcOffset, little);
      view.setUint32(descriptor + 4, 32, little);
      view.setUint32(descriptor + 8, rowOffset, little);
      view.setUint32(descriptor + 12, 1, little);
      bytes[descriptor + 16] = 1;
    }
    view.setUint16(data + attrSize, 4, little);
    bytes.set([7, 32, 248, 240], data + attrSize + 2); // SP, CFA +32, RA -8, FP -16.
  }
  return { bytes, view, descriptorStart, rowStart };
};

// Minimal ELF64 image with matching section and segment headers, or a segment alone.
export const sframeElf = (payload: Uint8Array, little = true, source = "both") => {
  const hasSections = source !== "segment";
  const offset = 256;
  const address = 0x402000n;
  const bytes = new Uint8Array(offset + payload.length);
  const view = new DataView(bytes.buffer);
  bytes.set([0x7f, 69, 76, 70, 2, little ? 1 : 2, 1]);
  view.setUint16(16, source === "object" ? 1 : 2, little);
  view.setUint16(18, 183, little); // EM_AARCH64 supports either byte order.
  view.setUint32(20, 1, little);
  view.setUint16(52, 64, little);
  if (source === "segment" || source === "both") {
    view.setBigUint64(32, 64n, little);
    view.setUint16(54, 56, little);
    view.setUint16(56, 1, little);
    view.setUint32(64, 0x6474e554, little); // PT_GNU_SFRAME, binutils include/elf/common.h.
    view.setUint32(68, 4, little);
    view.setBigUint64(72, BigInt(offset), little);
    view.setBigUint64(80, address, little);
    view.setBigUint64(96, BigInt(payload.length), little);
    view.setBigUint64(104, BigInt(payload.length), little);
  }
  if (hasSections) {
    view.setBigUint64(40, 128n, little);
    view.setUint16(58, 64, little);
    view.setUint16(60, 2, little);
    view.setUint32(196, 0x6ffffff4, little); // SHT_GNU_SFRAME, binutils include/elf/common.h.
    view.setBigUint64(200, 2n, little);
    view.setBigUint64(208, source === "object" ? 0n : address, little);
    view.setBigUint64(216, BigInt(offset), little);
    view.setBigUint64(224, BigInt(payload.length), little);
    view.setBigUint64(240, 4n, little);
  }
  bytes.set(payload, offset);
  return bytes;
};

export const sframeIsaElf = (): Uint8Array<ArrayBuffer> => {
  const bytes = sframeElf(sframePayload(3).bytes, true, "segment");
  const view = new DataView(bytes.buffer);
  const codeOffset = 192;
  const codeAddress = 0x400ffcn;
  // Second ELF64 program header, PT_LOAD with PF_R|PF_X (ELF gABI §7).
  view.setUint16(56, 2, true);
  view.setUint32(120, 1, true);
  view.setUint32(124, 5, true);
  view.setBigUint64(128, BigInt(codeOffset), true);
  view.setBigUint64(136, codeAddress, true);
  view.setBigUint64(152, 36n, true);
  view.setBigUint64(160, 36n, true);
  // A64 RET; NOP; RET. Only the latter pair is reached from the SFrame PC.
  view.setUint32(codeOffset, 0xd65f03c0, true);
  view.setUint32(codeOffset + 4, 0xd503201f, true);
  view.setUint32(codeOffset + 8, 0xd65f03c0, true);
  return bytes;
};
