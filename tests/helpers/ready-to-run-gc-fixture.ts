import { managedGcContainerFixture } from "./managed-gc-container-fixture.js";
import { createReadyToRunRendererFixture } from "./ready-to-run-renderer-fixture.js";

export const readyToRunGcFixture = () => {
  const source = managedGcContainerFixture();
  const data = createReadyToRunRendererFixture();
  const { exceptionDirectoryRva, methodRva, alignedGcInfoRva, rootUnwindRva,
    nativeOnlyMethodRva, runtimeFunctionBytes } = source.layout;
  // ReadyToRun section IDs 102/103 are RuntimeFunctions/MethodDefEntryPoints.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Runtime/ReadyToRunConstants.cs
  data.sections = [{ type: 102, name: "RuntimeFunctions", rva: exceptionDirectoryRva,
    size: runtimeFunctionBytes * 2 },
    { type: 103, name: "MethodDefEntryPoints", rva: 0, size: 0, decoded: { kind: "methods",
      methods: [{ methodRid: 1, runtimeFunctionIndex: 0, fixupOffset: null },
        { methodRid: 2, runtimeFunctionIndex: 1, fixupOffset: null }] } }];
  source.view.setUint32(exceptionDirectoryRva, methodRva, true);
  source.view.setUint32(exceptionDirectoryRva + 8, rootUnwindRva, true);
  source.view.setUint32(exceptionDirectoryRva + runtimeFunctionBytes, nativeOnlyMethodRva, true);
  source.view.setUint32(exceptionDirectoryRva + runtimeFunctionBytes + 8, rootUnwindRva, true);
  source.bytes[rootUnwindRva] = 1;
  source.bytes.set(source.gc, alignedGcInfoRva);
  return { ...source, data };
};
