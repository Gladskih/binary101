import { MockFile } from "./mock-file.js";
import type { PeClrReadyToRunSection } from "../../analyzers/pe/clr/ready-to-run-types.js";

export const thunkSectionFixture = (code: Uint8Array =
  Uint8Array.from(Buffer.from("ff25fa2e0000ccccff25f22e0000", "hex"))) => {
  const bytes = new Uint8Array(0x4000);
  bytes.set(code, 0x100);
  const section: PeClrReadyToRunSection =
    { type: 106, name: "DelayLoadMethodCallThunks", rva: 0x100, size: code.length };
  return { bytes, reader: new MockFile(bytes), section, issues: [] as string[] };
};

export const largeThunkSectionFixture = () => {
  const count = 10000;
  const bytes = new Uint8Array(0x100 + count * 8 + 8);
  const code = Uint8Array.from(Buffer.from("ff25faffffffcccc", "hex"));
  for (let index = 0; index < count; index++) bytes.set(code, 0x100 + index * 8);
  const section: PeClrReadyToRunSection =
    { type: 106, name: "DelayLoadMethodCallThunks", rva: 0x100, size: count * 8 };
  return { count, reader: new MockFile(bytes), section, issues: [] as string[] };
};
