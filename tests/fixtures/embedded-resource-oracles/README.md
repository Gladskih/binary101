Ordinary unit, coverage, E2E and mutation tests build resource fixtures in memory
from TypeScript sources. They need no Qt, GLib, C++ compiler, WSL or generated files.

An optional independent check uses genuine Qt/GLib outputs generated into
`generated/embedded-resource-oracles/`, which is ignored by Git.
Do not commit the generated RCC, GResource, PE, ELF or object files.

On Debian/Ubuntu (or the default WSL distribution on Windows), install:

```sh
sudo apt-get update
sudo apt-get install -y --no-install-recommends qtbase5-dev-tools qt6-base-dev-tools \
  libglib2.0-dev-bin g++ g++-mingw-w64-x86-64 python3
```

Run `npm run test:embedded-resources:oracles` to build fixtures using the upstream
Qt and GLib tools and test the analyzers against them. This command is separate
from the default tests and CI.

The original test payloads and all build instructions are in
[`scripts/build-embedded-resource-oracles.sh`](../../../scripts/build-embedded-resource-oracles.sh).
These are analysis fixtures with registration stubs; they are never executed.
