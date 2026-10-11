"use strict";

import { createPeDataSeedFixture } from "./pe-data-seeds.js";
import { msvcRttiFixtureRvaToOffset } from "./pe-msvc-rtti-pe.js";
import { createPePlusDirectIatReferenceFile } from "./pe-direct-iat-reference-file.js";

export const createPeFallthroughDataFile = async (): Promise<File> => {
  const { file, targets } = createPeDataSeedFixture();
  const bytes = new Uint8Array(await file.arrayBuffer());
  bytes.fill(0x90, msvcRttiFixtureRvaToOffset(targets[0]!)!,
    msvcRttiFixtureRvaToOffset(targets[1]!)!);
  return new File([bytes], "fallthrough-data.dll");
};

export const createPeNoReturnFile = (): Uint8Array<ArrayBuffer> => {
  const bytes = createPePlusDirectIatReferenceFile().data.slice();
  const view = new DataView(bytes.buffer);
  // This PE32+ fixture maps entry RVA 0x1000 to raw offset 0x200.
  // CALL [RIP+disp32] originally selects Sleep; the next 8-byte IAT slot is ExitProcess.
  view.setInt32(0x202, view.getInt32(0x202, true) + 8, true);
  // Intel SDM Vol. 2: MOVAPS xmm0, xmm0 / RET. These bytes must not follow ExitProcess.
  bytes.set([0x0f, 0x28, 0xc0, 0xc3], 0x206);
  return bytes;
};
