# AMD64 Windows unwind reproductions

These fixtures exercise Windows `RtlVirtualUnwind` on actual CPU contexts captured while
calling small functions. They support investigation of PE exception-directory diagnostics in
Binary101.

## DMD optimized frameless function

`probe.d` contains a four-line function with no imports. DMD 2.114.0 produces the following
code with `-m64 -O -c`.

```asm
+0x00  48 8d 41 01        lea rax, [rcx + 1]
+0x04  48 35 2a 00 00 00  xor rax, 42
+0x0a  c3                 ret
```

The COFF object already contains these unwind properties, before linking.

```text
Version: 1
Flags: 0
PrologSize: 0
FrameRegister: RBP
FrameOffset: 0
UnwindCodeCount: 2
0x04: SET_FPREG reg=RBP, offset=0
0x01: PUSH_NONVOL reg=RBP
```

The function leaves RBP and RSP unchanged. At offset `+4`, Windows uses these unwind codes
and recovers an incorrect caller context. With the supplied assembly caller, RSP advances
by 56 bytes while the expected advance is 8 bytes. RBP and RIP also differ from the actual
caller's values. The function itself completes and returns zero.

At offset `+0`, Windows skips the later unwind codes. At `+10`, it recognizes the return
instruction as an epilogue. Both checkpoints pass. The failing checkpoint is `+4`.

DMD 2.114.0 also reproduces with `-betterC -O`. DMD 2.112.0 reproduces with `-O`.
The 2.114.0 `-g` build establishes an RBP frame and passes the checks below.
The optimized `-O -gs` build also establishes a frame and passes.
Microsoft LINK and LLVM LLD both preserve the failing optimized metadata and reproduce
the incorrect caller context. The introduction version of the defect is unknown.

The backend emits the two fixed RBP unwind operations in `unwind_info_slice`.
[Released DMD source](https://github.com/dlang/dmd/blob/5314be988e3d495d969bf28a04270f02ca49e2e4/compiler/src/dmd/backend/pdata.d#L263-L298)

## Build

Use an x64 Visual Studio tools prompt with MSVC, MASM and the Windows SDK. Pass the DMD
executable and an existing output directory. The build script writes its products there.

From the repository root, in Developer PowerShell configured for x64, run the following
commands. Set `$reproDmd` to the full compiler path when DMD is outside PATH.

```powershell
$reproDmd = (Get-Command dmd.exe).Source
$reproOutput = New-Item -ItemType Directory -Force scan-results/amd64-unwind-repros
& ./tests/external/amd64-unwind-repros/build.cmd $reproDmd $reproOutput.FullName
if ($LASTEXITCODE -ne 0) { throw "Reproduction build failed" }
Push-Location $reproOutput.FullName
```

The build creates the checker, four DMD DLL variants and two MASM controls.
Each DLL exports `probe`, has no entry point, and links with `/NODEFAULTLIB`.

The object and final DLL can also be inspected independently with LLVM tools.

```powershell
llvm-readobj --unwind probe-optimized.obj
llvm-objdump -d probe-optimized.dll
```

## Run

Run the checker in a standalone console. The optional offset selects an instruction
boundary in the supplied function. The following results were verified on Windows x64
10.0.26300 with DMD 2.114.0 and MSVC 19.51.36244.

| Command | Expected exit | Result |
| --- | --- | --- |
| `./entry-check.exe ./probe-optimized.dll 0` | 0 | Entry context restored |
| `./entry-check.exe ./probe-optimized.dll 4` | 1 | RSP, RBP and RIP differ |
| `./entry-check.exe ./probe-optimized.dll 10` | 0 | Epilogue context restored |
| `./entry-check.exe ./probe-betterc.dll 4` | 1 | Same three differences |
| `./entry-check.exe ./probe-debug.dll 4` | 0 | Caller context restored |
| `./entry-check.exe ./probe-framed.dll 8` | 0 | Caller context restored |
| `./entry-check.exe ./leaf-control.dll 4` | 0 | Caller context restored |
| `./entry-check.exe ./frame-control.dll 8` | 0 | Caller context restored |

The optimized failing case prints the following output.

```text
traps=2 functionResult=0
checkpoint=4 fault=0 rspDelta=56 expectedDelta=8 rspOk=0 rbpOk=0 ripOk=0
```

Exit 0 means the three caller values match. Exit 1 reports an unwind difference or native
unwind fault. Exit 2 reports a setup or invocation error.

The checker first captures the real entry context using an in-process INT3 and a vectored
exception handler. It records the caller's RSP, RBP and return address before the function
executes. For a later checkpoint, it resumes execution until that boundary and then calls
`RtlVirtualUnwind` on a copy of the captured context. The original instruction bytes are
restored before the unwind call. The live context resumes at the original instruction and
the function returns normally. The DLL files on disk retain their original bytes.

`call-probe.asm` provides the Win64 shadow space, stack alignment and a real caller frame.
`leaf-control.asm` computes the same expression with an empty unwind-code array.

The expected caller values come directly from the captured function entry. The checker
uses the system unwinder and the loaded DLL's runtime-function entry. Its check covers
RSP, RBP and RIP at the selected boundary.

## PPEE frame-pointer diagnostic

`frame-control.asm` establishes RBP before subtracting 32 bytes from RSP. Its two unwind
codes record the RBP push and frame-pointer establishment. Windows restores RSP from
RBP during unwinding, which also discards that later allocation.

PPEE CLI 2.0.0-pre emits `prolog_undescribed` for this fixture.

```powershell
ppee-cli --no-update-check --no-similarity --exception --json frame-control.dll
```

The diagnostic text is `"sub rsp, 0x20" changes the stack in the prologue, but no unwind
code describes it`. Windows restores the recorded caller values at all instruction
boundaries in this fixture, including `+8`, immediately after the subtraction.
Verified offsets are 0, 1, 4, 8, 9, 13, 17, 21 and 22.

The reported absence of a separate allocation code is observable. The documentation's
claim that this necessarily produces stack drift needs clarification for an RBP-anchored
frame. This fixture supports that diagnostic discussion.
[PPEE exception-directory documentation](https://mzrst.com/puppy/docs/features/data-directories/exception/)

## References

- [Microsoft x64 exception handling](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64)
- [Microsoft x64 prolog and epilog](https://learn.microsoft.com/en-us/cpp/build/prolog-and-epilog)
- [Microsoft x64 calling convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention)
- [RtlVirtualUnwind](https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtlvirtualunwind)

The fixtures are manual native reference tests. Their build and execution use local tools.
