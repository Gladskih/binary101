import config from "../stryker.config.json" with { type: "json" };

export default {
  ...config,
  mutate: [
    "analyzers/embedded-resources/*.ts",
    "analyzers/pe/embedded-resources.ts",
    "analyzers/elf/embedded-resources.ts"
  ],
  testFiles: [
    "tests/unit/analyzers/embedded-resources/*.test.ts",
    "tests/unit/analyzers/pe/embedded-resources.test.ts",
    "tests/unit/analyzers/elf/embedded-resources.test.ts"
  ],
  concurrency: 6,
  incrementalFile: "reports/mutation/stryker-incremental.qt-glib.json",
  // Bound faulted test runners without restricting the TypeScript checker's heap.
  tap: { ...config.tap, nodeArgs: ["--max-old-space-size=512", ...config.tap.nodeArgs] }
};
