# Qt RCC corpus laboratory

This is an explicit research tool, separate from ordinary tests and CI. It does
not change the production detector. The controller currently runs on Windows
with WSL and an MSYS2 UCRT64 Python/toolchain. Python 3.14 and Node 26 are used.
All executables, SDKs, maps, logs, labels and scanner results stay outside Git.
Commands acquire an OS-released single-writer lock on the output directory;
overlapping build/scan/report invocations fail before changing corpus state.

## Prepare and validate

Use a new external output directory for an experiment. The examples use
`C:/Users/glads/source/worktree-artifacts/qt-rcc-corpus-20261031`.

```powershell
npm run research:qt-rcc -- doctor --out C:/path/to/artifacts
npm run research:qt-rcc -- selftest --out C:/path/to/artifacts
npm run research:qt-rcc -- smoke --out C:/path/to/artifacts --workers 2 --minutes 10
npm run research:qt-rcc -- scan --out C:/path/to/artifacts --workers 2
npm run research:qt-rcc -- evaluate --out C:/path/to/artifacts
```

`doctor` discovers actual kit versions. Native ELF builds use GCC/Clang and
Qt 5/6 development packages in WSL. PE builds use UCRT64 GCC/Clang plus the
MSYS2 `qt5-base`, `qt6-base`, `qt5-static`, `qt6-static`, `make` packages.
These are prerequisites, never installed automatically by normal tests.
Set `QT_LAB_PYTHON`, `QT_LAB_WINDOWS_PYTHON`, or `QT_LAB_UCRT64` to override paths.
SDK environment snapshots contain only required overrides, not arbitrary secrets.

Optional native static SDK preparation is a separate command and time budget:

```sh
python3 scripts/qt-resource-lab/bootstrap_linux.py --major 5 --jobs 4
python3 scripts/qt-resource-lab/bootstrap_linux.py --major 6 --jobs 4
```

Run these inside WSL; install compiler, Perl, CMake, Ninja, development libraries
and `/usr/bin/time` first. Source URLs and the first downloaded SHA256 are frozen
in the external cache. Qt 5's Git source archive needs header synchronization;
the preparation command performs it explicitly. Static Qt itself is built
without LTO. Application LTO is recorded separately; other kits' Qt LTO status
is unknown unless independently established.

## Pilot and larger batches

```powershell
npm run research:qt-rcc -- pilot --out C:/path/to/artifacts --workers 4 --minutes 15
npm run research:qt-rcc -- scan --out C:/path/to/artifacts --workers 4
npm run research:qt-rcc -- evaluate --out C:/path/to/artifacts
npm run research:qt-rcc -- gate --out C:/path/to/artifacts
npm run research:qt-rcc -- build --out C:/path/to/artifacts --workers 8 --minutes 180
```

The pilot covers SDK/linkage/target pairs, both labels, compiler optimization
profiles and every source family. It is larger than smoke but much smaller
than the complete Cartesian schedule. A bulk batch requires all eight
format/Qt-major/linkage cells, successful pilot labels and scanner responses,
passing evaluator tests, and at least 50% measured CPU capacity utilization.
The gate is tied to the build recipe and pilot input hashes.

Each command has a deadline and 1.5 GiB address-space/job-memory bound. Windows
uses suspended creation plus Job Objects, covering descendant CPU and memory;
Linux uses process groups, RLIMIT_AS and GNU time child accounting. The batch
stops submitting work on budget exhaustion, three failures in the latest eight
jobs, memory pressure, or sustained CPU utilization below 50% of worker capacity.
Active jobs finish within their individual deadlines. Non-CPU time is an upper
bound on waiting/overhead, not a measured I/O-wait percentage.
Repeated preparation failures also stop submission even when separated by many
successful jobs. A stopped/failed batch is not reported as a completed experiment.

Job results resume only when the recipe and published input hashes match.
Failures remain explicit and are retried. A changed scanner gets a separate
cache. Build success does not imply detector success: known scanner misses are
legitimate evaluation results and do not block the laboratory gate.
Smoke and pilot always rebuild to measure real work; a bulk run resumes completed
jobs. SDK discovery probes `rcc` compression support and writes unsupported
algorithm/SDK cells to `unsupported-cells.json` instead of attempting them.

## Ground truth and scanner protocol

The producer is genuine `rcc`, linked against genuine Qt. The oracle enumerates
through Qt, reads through Qt, hashes contents, identifies the module owning the
stored data pointer, and maps it independently to file offsets. Source manifests
confirm aliases/locales/content; dependencies' resources are excluded by owner.
Unused arrays are retained without registration, compared with the producer's
actual bytes, and checked by a separate Qt consumption of the corresponding
`qres` container. Stripped twins must lose symbols and retain resource bytes.

`samples.jsonl` contains only opaque `id`, `path`, and input `sha256`.
Ground truth, build parameters, maps and symbol evidence are separate in
`labels.jsonl` and job records. Public sample IDs and asset prefixes do not
contain positive/negative family names. Never feed labels or sidecars to a scanner.

A scanner is a command argv array in a JSON file supplied with `scan --scanner`.
Custom scanners are rerun by default. Supply `--scanner-revision` with an immutable
version covering their dependencies to enable reuse. The baseline fingerprint
also hashes untracked analyzer sources, so editing a new detector invalidates
old scanner results.
It receives one JSON line `{ "id": "...", "path": "..." }` on stdin and returns:

```json
{"id":"...","status":"ok","bundles":[{"offset":123,"files":[{"path":"/icon.svg","sha256":"64 hex digits","offset":456,"language":1,"territory":0}]}]}
```

`files` means resource files, not directories. Paths start with `/`. Offsets are
absolute file offsets of stored contents, excluding RCC length prefixes and the
qCompress expanded-size prefix. SHA256 covers expanded contents. `error`,
`timeout`, and `unsupported` are distinct statuses. Exactly one matching reply
is required. The built-in adapter evaluates Qt RCC only and uses bounded disk
reads. It receives no expected data or auxiliary symbols.

## Real files and reports

`real --out ...` imports local shipping Qt files. A SHA256-pinned Logi Qt5Widgets
case has LLVM-audited registration arguments and independent Qt-consumer checks.
Its known bundles are partially labelled; additional content is unscored rather
than falsely called FP. Other shipping modules remain `unknown` until verified.
No installed third-party executable is launched by this command.

After each larger build run, repeat `scan`, `evaluate`, and `report`. Reports
separate file/resource/bundle TP/FP/FN, duplicate predictions, wrong content,
metadata differences, process failures and unscored truth. Identical file hashes
are counted once in totals. Raw per-sample results remain available.
Source families are deterministically split before scanning; compiler/strip
variants of one family stay together. Real shipping files are held out.
Build variants are correlated: `0/N` never proves a zero false-positive rate.
Unknown module inventories do not enter precision/recall denominators.
The current build matrix targets x86-64; MSVC, other architectures, and LTO
inside the prebuilt Qt libraries are not claimed as covered.

`selftest` runs SDK-independent Python conformance tests, including process
accounting/timeout tests and lock/cache integrity. `mutate-evaluator` independently
reruns the evaluator tests against comparisons, set operations, booleans and
integer changes. Its raw results include every surviving mutant. These are
explicit research checks and are not hooked into ordinary npm tests.

Negative-label evidence includes offsets and hashes of decoy bytes retained in
each final image. A missing/optimized-away decoy prevents a verified label.
Resource matching uses path plus stored-content offset; wrong content and locale
metadata are counted separately from detection FP/FN.

Independent-oracle layout references: [PE/COFF](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format),
[ELF program headers](https://gabi.xinuos.com/elf/07-pheader.html),
[Qt raw resource data](https://doc.qt.io/qt-6/qresource.html#data), and
[Windows job accounting](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_accounting_information).
Windows peak memory is job committed memory; Linux reports GNU time's maximum
resident set size across children. These memory figures are not interchangeable.
