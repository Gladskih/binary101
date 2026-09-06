# PE special instructions: implementation and disk validation

Validated on 2026-09-06 using the same control-flow ISA analyzer and seed collector as the browser. All 12 categories were found in installed Windows PE files. Each instruction found in this scan has its own glossary explanation.

Purpose and CPU-privilege tags can coexist on one row. Counts are decoded sites; up to three RVA examples are retained per mnemonic. Selecting an example opens disassembly at that address. Category and instruction explanations use native details/summary controls, available to keyboard and touch users.

This is a static sample of reachable code, not execution evidence. It can miss indirect or generated code and can encounter invalid decodes. CPUID/timestamp instructions do not establish anti-debugging intent, and security instructions do not establish that a protection is enabled.

## Real-file evidence

All paths below are under `C:/Windows/System32/`. Counts describe the listed instruction in that file, not category totals.

| Category | PE file | Instruction | Example RVA | Sites |
| --- | --- | --- | --- | ---: |
| Direct syscall | ntdll.dll | SYSCALL | 0x001603c2 | 494 |
| Kernel privilege | ntoskrnl.exe | HLT | 0x006a73de | 6 |
| I/O privilege | ntoskrnl.exe | CLI | 0x006a9703 | 804 |
| Trap / interrupt | ntdll.dll | INT3 | 0x0011ece0 | 183 |
| Virtualization | hvix64.exe | VMXON | 0x00340a5e | 1 |
| Hypervisor call | ntoskrnl.exe | VMCALL | 0x006b67d0 | 1 |
| CPU capabilities | ntdll.dll | CPUID | 0x00109ad3 | 7 |
| Timing / counters | ntdll.dll | RDTSC | 0x000d58d3 | 39 |
| System state | ntoskrnl.exe | MOV CR | 0x00b4d44c | 5670 |
| Cache / address translation | ntoskrnl.exe | INVLPG | 0x00296f19 | 16 |
| Hardware security | ntdll.dll | RDSSPQ | 0x0011f012 | 1 |
| Transactional memory | ntoskrnl.exe | XBEGIN | 0x00514af6 | 3 |

AMD virtualization was also confirmed with VMRUN, VMLOAD and VMSAVE in hvax64.exe. Intel VMXON, VMREAD/VMWRITE, VMLAUNCH/VMRESUME and translation invalidation operations were found in hvix64.exe.

## File identities and scan scope

| File | SHA-256 | Decoded instructions | Analyzer notes |
| --- | --- | ---: | ---: |
| ntoskrnl.exe | 13aa072103656881bab86c09ac0f8362265783bbfb428e85ff060e6018ec2488 | 2584707 | 6 |
| hvix64.exe | bcb0fc2d234e2a9d84577c8cfada7e8d47e02bd7b55817bccdcbf4fb789d8d21 | 432353 | 1 |
| hvax64.exe | 181ec112210fa9f67ca23c6eb8b8699d2059c85a82f1717221431af2c2239157 | 413713 | 1 |
| ntdll.dll | b9775b65c47564c2571fb9175e07ec14ce2a771613230afb2c284a0501a369a7 | 365306 | 0 |
| kernelbase.dll | 9d26852459745322b704e2a49e448922839c584d06e208cf9abcd0d857c4b7cd | 400265 | 0 |
| securekernel.exe | bd20f9cdc7dd7b3b75bba3060530e0f213f3ef344cf7800f1b73618a6669ac6b | 233925 | 3 |

Total: 4,430,269 decoded instructions across six files.

The kernel reports invalid instruction decodes and a seed in a non-executable INITDATA section; the hypervisors also report seeds in non-executable .data. These are retained analyzer notes, not silently discarded failures. The scan is not an exhaustive inventory of the drive.

## Reproduce

```powershell
npx tsx scripts/peSpecialInstructionScan.ts C:/Windows/System32/ntoskrnl.exe C:/Windows/System32/hvix64.exe C:/Windows/System32/hvax64.exe C:/Windows/System32/ntdll.dll C:/Windows/System32/kernelbase.dll C:/Windows/System32/securekernel.exe
```

The CLI appends timestamped reports with file sizes, SHA-256, parse warnings, analyzer notes and findings to `scan-results/isa/pe-special-instructions.jsonl`. It reads files locally and streams hashes with bounded memory. The per-file ISA analysis budget is 120 seconds; cancellation is retained in analyzer notes. These six runs completed without cancellation. The budget applies to ISA analysis, not initial PE parsing or hashing.

## References and interpretation

Instruction semantics follow [Intel SDM, volumes 2 and 3](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html), [Intel instruction extensions](https://cdrdv2-public.intel.com/671368/architecture-instruction-set-extensions-programming-reference.pdf) and [AMD APM, volume 3](https://docs.amd.com/v/u/en-US/24594_3.37). Privilege tags use iced-x86 1.21.0 metadata, which separates CPL=0/IOPL restrictions and excludes VMCALL from its privileged flag.

MOV control/debug-register accesses are recognized from validated register operands. INT 2Eh is labelled as the historical Windows syscall gateway. Uncatalogued privileged instructions remain visible with an explicit statement that their exact operation is not yet described; they are not assigned guessed semantics.

## Verification and CONTRIBUTING.md audit

- Lint, typecheck, production build and all 81 browser tests pass.
- Coverage: 96.17% statements/lines, 83.98% branches, 96.60% functions (baseline 96.16%, 83.94%, 96.57%). The classifier, catalog, special-instruction renderer and navigation handler have 100% coverage on all metrics.
- Mutation testing: 97.37% overall, 100% for rendering and navigation. The three surviving classifier mutations are equivalent for the supported decoder metadata (fallback labels or register-name matching); no uncovered mutants remain. Reports are under `reports/mutation/`.
- Reviewed final changes against CONTRIBUTING.md: bounded RVAs and example storage; decoder operands checked before access; no extra instruction pass in browser analysis; pure analyzer data and separate HTML formatting; no new dependencies or services; unchanged parseForUi contract; semantic tables and accessible explanations; module/function size and lint constraints checked.
- Build succeeds with the existing warning about a JavaScript chunk exceeding 500 kB; no chunk-size refactor is included.
