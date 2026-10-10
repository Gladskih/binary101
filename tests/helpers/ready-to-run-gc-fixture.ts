import { managedGcContainerFixture } from "./managed-gc-container-fixture.js";
import { createReadyToRunRendererFixture } from "./ready-to-run-renderer-fixture.js";

export const readyToRunGcFixture = () => {
  const source = managedGcContainerFixture();
  const data = createReadyToRunRendererFixture();
  data.sections = [{ type: 102, name: "RuntimeFunctions", rva: 128, size: 24 },
    { type: 103, name: "MethodDefEntryPoints", rva: 0, size: 0, decoded: { kind: "methods",
      methods: [{ methodRid: 1, runtimeFunctionIndex: 0, fixupOffset: null },
        { methodRid: 2, runtimeFunctionIndex: 1, fixupOffset: null }] } }];
  source.view.setUint32(128, 32, true);
  source.view.setUint32(136, 64, true);
  source.view.setUint32(140, 40, true);
  source.view.setUint32(148, 64, true);
  source.bytes[64] = 1;
  source.bytes.set(source.gc, 72);
  return { ...source, data };
};
