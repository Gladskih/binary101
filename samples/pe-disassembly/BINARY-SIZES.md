# PE Disassembly Sample Binary Sizes

Generated from `summary.json` by `scripts/pe-disassembly-samples/size-table.ts`.

The build pipeline validates primary PE outputs before they enter `summary.json`.
Those outputs should have no COFF symbol records in the executable.
The authentic Go internal linker may leave an empty COFF pointer with zero records.
Adjacent PDB files may still exist for toolchains that emit them.

| language | arch | compiler | mode | runtime linkage | size bytes | size KiB | variant id |
|---|---|---|---|---|---:|---:|---|
| c | x64 | MSVC cl.exe | od-md | DLL MSVC CRT | 9728 | 9.5 | c-msvc-x64-od-md |
| c | x64 | MSVC cl.exe | o2-md | DLL MSVC CRT | 9728 | 9.5 | c-msvc-x64-o2-md |
| c | x64 | MSVC cl.exe | o2-mt | static MSVC CRT | 111104 | 108.5 | c-msvc-x64-o2-mt |
| c | x64 | MSVC cl.exe | o2-md-ltcg | DLL MSVC CRT | 9728 | 9.5 | c-msvc-x64-o2-md-ltcg |
| c | x64 | MSVC cl.exe | o2-md-arch-avx2 | DLL MSVC CRT | 9728 | 9.5 | c-msvc-x64-o2-md-arch-avx2 |
| c | x64 | MSVC cl.exe | o2-md-arch-avx512 | DLL MSVC CRT | 9728 | 9.5 | c-msvc-x64-o2-md-arch-avx512 |
| c | x86 | MSVC cl.exe | od-md | DLL MSVC CRT | 8192 | 8.0 | c-msvc-x86-od-md |
| c | x86 | MSVC cl.exe | o2-md | DLL MSVC CRT | 8192 | 8.0 | c-msvc-x86-o2-md |
| c | x86 | MSVC cl.exe | o2-mt | static MSVC CRT | 92160 | 90.0 | c-msvc-x86-o2-mt |
| c | x86 | MSVC cl.exe | o2-md-ltcg | DLL MSVC CRT | 8192 | 8.0 | c-msvc-x86-o2-md-ltcg |
| c | x64 | LLVM clang-cl | od-md | DLL MSVC CRT | 8704 | 8.5 | c-clang-cl-x64-od-md |
| c | x64 | LLVM clang-cl | o2-md | DLL MSVC CRT | 8704 | 8.5 | c-clang-cl-x64-o2-md |
| c | x64 | LLVM clang-cl | o2-mt | static MSVC CRT | 117248 | 114.5 | c-clang-cl-x64-o2-mt |
| c | x64 | LLVM clang-cl | o2-md-flto | DLL MSVC CRT | 8704 | 8.5 | c-clang-cl-x64-o2-md-flto |
| c | x64 | LLVM clang-cl | o2-md-march-x86-64-v2 | DLL MSVC CRT | 8704 | 8.5 | c-clang-cl-x64-o2-md-march-x86-64-v2 |
| c | x64 | LLVM clang-cl | o2-md-march-x86-64-v3 | DLL MSVC CRT | 8704 | 8.5 | c-clang-cl-x64-o2-md-march-x86-64-v3 |
| c | x64 | LLVM clang-cl | o2-md-mtune-znver5 | DLL MSVC CRT | 8704 | 8.5 | c-clang-cl-x64-o2-md-mtune-znver5 |
| c | x64 | LLVM clang-cl | o2-md-march-znver5 | DLL MSVC CRT | 8704 | 8.5 | c-clang-cl-x64-o2-md-march-znver5 |
| c | x86 | LLVM clang-cl | od-md | DLL MSVC CRT | 7680 | 7.5 | c-clang-cl-x86-od-md |
| c | x86 | LLVM clang-cl | o2-md | DLL MSVC CRT | 7680 | 7.5 | c-clang-cl-x86-o2-md |
| c | x86 | LLVM clang-cl | o2-mt | static MSVC CRT | 91136 | 89.0 | c-clang-cl-x86-o2-mt |
| c | x86 | LLVM clang-cl | o2-md-flto | DLL MSVC CRT | 7680 | 7.5 | c-clang-cl-x86-o2-md-flto |
| c | x64 | MSYS2 UCRT64 GCC/G++ | o0 | MSYS2 UCRT DLLs | 18432 | 18.0 | c-msys-ucrt64-x64-o0 |
| c | x64 | MSYS2 UCRT64 GCC/G++ | o2 | MSYS2 UCRT DLLs | 17920 | 17.5 | c-msys-ucrt64-x64-o2 |
| c | x64 | MSYS2 UCRT64 GCC/G++ | os | MSYS2 UCRT DLLs | 17920 | 17.5 | c-msys-ucrt64-x64-os |
| c | x64 | MSYS2 UCRT64 GCC/G++ | o2-march-x86-64-v2 | MSYS2 UCRT DLLs | 17920 | 17.5 | c-msys-ucrt64-x64-o2-march-x86-64-v2 |
| c | x64 | MSYS2 UCRT64 GCC/G++ | o2-march-x86-64-v3 | MSYS2 UCRT DLLs | 17920 | 17.5 | c-msys-ucrt64-x64-o2-march-x86-64-v3 |
| c | x64 | MSYS2 UCRT64 GCC/G++ | o2-mtune-znver5 | MSYS2 UCRT DLLs | 17920 | 17.5 | c-msys-ucrt64-x64-o2-mtune-znver5 |
| c | x64 | MSYS2 UCRT64 GCC/G++ | o2-march-znver5 | MSYS2 UCRT DLLs | 17920 | 17.5 | c-msys-ucrt64-x64-o2-march-znver5 |
| c | x64 | MSYS2 UCRT64 GCC/G++ | o2-flto | MSYS2 UCRT DLLs | 17920 | 17.5 | c-msys-ucrt64-x64-o2-flto |
| c | x64 | MSYS2 UCRT64 clang/clang++ | o0 | MSYS2 UCRT DLLs | 16896 | 16.5 | c-msys-ucrt64-clang-x64-o0 |
| c | x64 | MSYS2 UCRT64 clang/clang++ | o2 | MSYS2 UCRT DLLs | 16896 | 16.5 | c-msys-ucrt64-clang-x64-o2 |
| c | x64 | MSYS2 UCRT64 clang/clang++ | os | MSYS2 UCRT DLLs | 16896 | 16.5 | c-msys-ucrt64-clang-x64-os |
| c | x64 | MSYS2 UCRT64 clang/clang++ | o2-march-x86-64-v2 | MSYS2 UCRT DLLs | 16896 | 16.5 | c-msys-ucrt64-clang-x64-o2-march-x86-64-v2 |
| c | x64 | MSYS2 UCRT64 clang/clang++ | o2-march-x86-64-v3 | MSYS2 UCRT DLLs | 16896 | 16.5 | c-msys-ucrt64-clang-x64-o2-march-x86-64-v3 |
| c | x64 | MSYS2 UCRT64 clang/clang++ | o2-mtune-znver5 | MSYS2 UCRT DLLs | 16896 | 16.5 | c-msys-ucrt64-clang-x64-o2-mtune-znver5 |
| c | x64 | MSYS2 UCRT64 clang/clang++ | o2-march-znver5 | MSYS2 UCRT DLLs | 16896 | 16.5 | c-msys-ucrt64-clang-x64-o2-march-znver5 |
| c | x64 | MSYS2 UCRT64 clang/clang++ | o2-flto | MSYS2 UCRT DLLs | 16384 | 16.0 | c-msys-ucrt64-clang-x64-o2-flto |
| c | x64 | MSYS2 CLANG64 clang/clang++ | o0 | MSYS2 CLANG64 DLLs | 13824 | 13.5 | c-msys-clang64-x64-o0 |
| c | x64 | MSYS2 CLANG64 clang/clang++ | o2 | MSYS2 CLANG64 DLLs | 13824 | 13.5 | c-msys-clang64-x64-o2 |
| c | x64 | MSYS2 CLANG64 clang/clang++ | os | MSYS2 CLANG64 DLLs | 13824 | 13.5 | c-msys-clang64-x64-os |
| c | x64 | MSYS2 CLANG64 clang/clang++ | o2-march-x86-64-v2 | MSYS2 CLANG64 DLLs | 13824 | 13.5 | c-msys-clang64-x64-o2-march-x86-64-v2 |
| c | x64 | MSYS2 CLANG64 clang/clang++ | o2-march-x86-64-v3 | MSYS2 CLANG64 DLLs | 13824 | 13.5 | c-msys-clang64-x64-o2-march-x86-64-v3 |
| c | x64 | MSYS2 CLANG64 clang/clang++ | o2-mtune-znver5 | MSYS2 CLANG64 DLLs | 13824 | 13.5 | c-msys-clang64-x64-o2-mtune-znver5 |
| c | x64 | MSYS2 CLANG64 clang/clang++ | o2-march-znver5 | MSYS2 CLANG64 DLLs | 13824 | 13.5 | c-msys-clang64-x64-o2-march-znver5 |
| c | x64 | MSYS2 CLANG64 clang/clang++ | o2-flto | MSYS2 CLANG64 DLLs | 13824 | 13.5 | c-msys-clang64-x64-o2-flto |
| c | x64 | LLVM clang/clang++ MSVC | o0 | DLL MSVC CRT | 117248 | 114.5 | c-llvm-clang-msvc-x64-o0 |
| c | x64 | LLVM clang/clang++ MSVC | o2 | DLL MSVC CRT | 117248 | 114.5 | c-llvm-clang-msvc-x64-o2 |
| c | x64 | LLVM clang/clang++ MSVC | os | DLL MSVC CRT | 117248 | 114.5 | c-llvm-clang-msvc-x64-os |
| c | x86 | LLVM clang/clang++ MSVC | o0 | DLL MSVC CRT | 91136 | 89.0 | c-llvm-clang-msvc-x86-o0 |
| c | x86 | LLVM clang/clang++ MSVC | o2 | DLL MSVC CRT | 91136 | 89.0 | c-llvm-clang-msvc-x86-o2 |
| c | x86 | LLVM clang/clang++ MSVC | os | DLL MSVC CRT | 91136 | 89.0 | c-llvm-clang-msvc-x86-os |
| c | x64 | LLVM clang/clang++ MSVC | o2-march-x86-64-v2 | DLL MSVC CRT | 117248 | 114.5 | c-llvm-clang-msvc-x64-o2-march-x86-64-v2 |
| c | x64 | LLVM clang/clang++ MSVC | o2-march-x86-64-v3 | DLL MSVC CRT | 117248 | 114.5 | c-llvm-clang-msvc-x64-o2-march-x86-64-v3 |
| c | x64 | LLVM clang/clang++ MSVC | o2-mtune-znver5 | DLL MSVC CRT | 117248 | 114.5 | c-llvm-clang-msvc-x64-o2-mtune-znver5 |
| c | x64 | LLVM clang/clang++ MSVC | o2-march-znver5 | DLL MSVC CRT | 117248 | 114.5 | c-llvm-clang-msvc-x64-o2-march-znver5 |
| c | x64 | LLVM clang/clang++ MSVC | o2-flto | DLL MSVC CRT | 117248 | 114.5 | c-llvm-clang-msvc-x64-o2-flto |
| c | x64 | Zig cc/c++ | o0 | Zig libc bundled | 73216 | 71.5 | c-zig-cc-x64-o0 |
| c | x64 | Zig cc/c++ | o2 | Zig libc bundled | 73728 | 72.0 | c-zig-cc-x64-o2 |
| c | x86 | Zig cc/c++ | o0 | Zig libc bundled | 82944 | 81.0 | c-zig-cc-x86-o0 |
| c | x86 | Zig cc/c++ | o2 | Zig libc bundled | 83456 | 81.5 | c-zig-cc-x86-o2 |
| c | x64 | Zig cc/c++ | o2-march-x86-64-v2 | Zig libc bundled | 73216 | 71.5 | c-zig-cc-x64-o2-march-x86-64-v2 |
| c | x64 | Zig cc/c++ | o2-march-x86-64-v3 | Zig libc bundled | 71680 | 70.0 | c-zig-cc-x64-o2-march-x86-64-v3 |
| c | x64 | Zig cc/c++ | o2-mtune-znver5 | Zig libc bundled | 71680 | 70.0 | c-zig-cc-x64-o2-mtune-znver5 |
| c | x64 | Zig cc/c++ | o2-march-znver5 | Zig libc bundled | 71680 | 70.0 | c-zig-cc-x64-o2-march-znver5 |
| cpp | x64 | MSVC cl.exe | od-md | DLL MSVC CRT | 12288 | 12.0 | cpp-msvc-x64-od-md |
| cpp | x64 | MSVC cl.exe | o2-md | DLL MSVC CRT | 10752 | 10.5 | cpp-msvc-x64-o2-md |
| cpp | x64 | MSVC cl.exe | o2-mt | static MSVC CRT | 213504 | 208.5 | cpp-msvc-x64-o2-mt |
| cpp | x64 | MSVC cl.exe | o2-md-ltcg | DLL MSVC CRT | 10752 | 10.5 | cpp-msvc-x64-o2-md-ltcg |
| cpp | x64 | MSVC cl.exe | o2-md-arch-avx2 | DLL MSVC CRT | 10752 | 10.5 | cpp-msvc-x64-o2-md-arch-avx2 |
| cpp | x64 | MSVC cl.exe | o2-md-arch-avx512 | DLL MSVC CRT | 10752 | 10.5 | cpp-msvc-x64-o2-md-arch-avx512 |
| cpp | x86 | MSVC cl.exe | od-md | DLL MSVC CRT | 11264 | 11.0 | cpp-msvc-x86-od-md |
| cpp | x86 | MSVC cl.exe | o2-md | DLL MSVC CRT | 10240 | 10.0 | cpp-msvc-x86-o2-md |
| cpp | x86 | MSVC cl.exe | o2-mt | static MSVC CRT | 175616 | 171.5 | cpp-msvc-x86-o2-mt |
| cpp | x86 | MSVC cl.exe | o2-md-ltcg | DLL MSVC CRT | 9728 | 9.5 | cpp-msvc-x86-o2-md-ltcg |
| cpp | x64 | LLVM clang-cl | od-md | DLL MSVC CRT | 11776 | 11.5 | cpp-clang-cl-x64-od-md |
| cpp | x64 | LLVM clang-cl | o2-md | DLL MSVC CRT | 10240 | 10.0 | cpp-clang-cl-x64-o2-md |
| cpp | x64 | LLVM clang-cl | o2-mt | static MSVC CRT | 220672 | 215.5 | cpp-clang-cl-x64-o2-mt |
| cpp | x64 | LLVM clang-cl | o2-md-flto | DLL MSVC CRT | 9728 | 9.5 | cpp-clang-cl-x64-o2-md-flto |
| cpp | x64 | LLVM clang-cl | o2-md-march-x86-64-v2 | DLL MSVC CRT | 10240 | 10.0 | cpp-clang-cl-x64-o2-md-march-x86-64-v2 |
| cpp | x64 | LLVM clang-cl | o2-md-march-x86-64-v3 | DLL MSVC CRT | 10240 | 10.0 | cpp-clang-cl-x64-o2-md-march-x86-64-v3 |
| cpp | x64 | LLVM clang-cl | o2-md-mtune-znver5 | DLL MSVC CRT | 10240 | 10.0 | cpp-clang-cl-x64-o2-md-mtune-znver5 |
| cpp | x64 | LLVM clang-cl | o2-md-march-znver5 | DLL MSVC CRT | 10240 | 10.0 | cpp-clang-cl-x64-o2-md-march-znver5 |
| cpp | x86 | LLVM clang-cl | od-md | DLL MSVC CRT | 10240 | 10.0 | cpp-clang-cl-x86-od-md |
| cpp | x86 | LLVM clang-cl | o2-md | DLL MSVC CRT | 8704 | 8.5 | cpp-clang-cl-x86-o2-md |
| cpp | x86 | LLVM clang-cl | o2-mt | static MSVC CRT | 175616 | 171.5 | cpp-clang-cl-x86-o2-mt |
| cpp | x86 | LLVM clang-cl | o2-md-flto | DLL MSVC CRT | 8704 | 8.5 | cpp-clang-cl-x86-o2-md-flto |
| cpp | x64 | MSYS2 UCRT64 GCC/G++ | o0 | MSYS2 UCRT DLLs | 18432 | 18.0 | cpp-msys-ucrt64-x64-o0 |
| cpp | x64 | MSYS2 UCRT64 GCC/G++ | o2 | MSYS2 UCRT DLLs | 18944 | 18.5 | cpp-msys-ucrt64-x64-o2 |
| cpp | x64 | MSYS2 UCRT64 GCC/G++ | os | MSYS2 UCRT DLLs | 18944 | 18.5 | cpp-msys-ucrt64-x64-os |
| cpp | x64 | MSYS2 UCRT64 GCC/G++ | o2-march-x86-64-v2 | MSYS2 UCRT DLLs | 18944 | 18.5 | cpp-msys-ucrt64-x64-o2-march-x86-64-v2 |
| cpp | x64 | MSYS2 UCRT64 GCC/G++ | o2-march-x86-64-v3 | MSYS2 UCRT DLLs | 18944 | 18.5 | cpp-msys-ucrt64-x64-o2-march-x86-64-v3 |
| cpp | x64 | MSYS2 UCRT64 GCC/G++ | o2-mtune-znver5 | MSYS2 UCRT DLLs | 18944 | 18.5 | cpp-msys-ucrt64-x64-o2-mtune-znver5 |
| cpp | x64 | MSYS2 UCRT64 GCC/G++ | o2-march-znver5 | MSYS2 UCRT DLLs | 18944 | 18.5 | cpp-msys-ucrt64-x64-o2-march-znver5 |
| cpp | x64 | MSYS2 UCRT64 GCC/G++ | o2-flto | MSYS2 UCRT DLLs | 18944 | 18.5 | cpp-msys-ucrt64-x64-o2-flto |
| cpp | x64 | MSYS2 UCRT64 clang/clang++ | o0 | MSYS2 UCRT DLLs | 16384 | 16.0 | cpp-msys-ucrt64-clang-x64-o0 |
| cpp | x64 | MSYS2 UCRT64 clang/clang++ | o2 | MSYS2 UCRT DLLs | 16384 | 16.0 | cpp-msys-ucrt64-clang-x64-o2 |
| cpp | x64 | MSYS2 UCRT64 clang/clang++ | os | MSYS2 UCRT DLLs | 16384 | 16.0 | cpp-msys-ucrt64-clang-x64-os |
| cpp | x64 | MSYS2 UCRT64 clang/clang++ | o2-march-x86-64-v2 | MSYS2 UCRT DLLs | 16384 | 16.0 | cpp-msys-ucrt64-clang-x64-o2-march-x86-64-v2 |
| cpp | x64 | MSYS2 UCRT64 clang/clang++ | o2-march-x86-64-v3 | MSYS2 UCRT DLLs | 16384 | 16.0 | cpp-msys-ucrt64-clang-x64-o2-march-x86-64-v3 |
| cpp | x64 | MSYS2 UCRT64 clang/clang++ | o2-mtune-znver5 | MSYS2 UCRT DLLs | 16384 | 16.0 | cpp-msys-ucrt64-clang-x64-o2-mtune-znver5 |
| cpp | x64 | MSYS2 UCRT64 clang/clang++ | o2-march-znver5 | MSYS2 UCRT DLLs | 16384 | 16.0 | cpp-msys-ucrt64-clang-x64-o2-march-znver5 |
| cpp | x64 | MSYS2 UCRT64 clang/clang++ | o2-flto | MSYS2 UCRT DLLs | 16384 | 16.0 | cpp-msys-ucrt64-clang-x64-o2-flto |
| cpp | x64 | MSYS2 CLANG64 clang/clang++ | o0 | MSYS2 CLANG64 DLLs | 19456 | 19.0 | cpp-msys-clang64-x64-o0 |
| cpp | x64 | MSYS2 CLANG64 clang/clang++ | o2 | MSYS2 CLANG64 DLLs | 15872 | 15.5 | cpp-msys-clang64-x64-o2 |
| cpp | x64 | MSYS2 CLANG64 clang/clang++ | os | MSYS2 CLANG64 DLLs | 16896 | 16.5 | cpp-msys-clang64-x64-os |
| cpp | x64 | MSYS2 CLANG64 clang/clang++ | o2-march-x86-64-v2 | MSYS2 CLANG64 DLLs | 15872 | 15.5 | cpp-msys-clang64-x64-o2-march-x86-64-v2 |
| cpp | x64 | MSYS2 CLANG64 clang/clang++ | o2-march-x86-64-v3 | MSYS2 CLANG64 DLLs | 15872 | 15.5 | cpp-msys-clang64-x64-o2-march-x86-64-v3 |
| cpp | x64 | MSYS2 CLANG64 clang/clang++ | o2-mtune-znver5 | MSYS2 CLANG64 DLLs | 15872 | 15.5 | cpp-msys-clang64-x64-o2-mtune-znver5 |
| cpp | x64 | MSYS2 CLANG64 clang/clang++ | o2-march-znver5 | MSYS2 CLANG64 DLLs | 15872 | 15.5 | cpp-msys-clang64-x64-o2-march-znver5 |
| cpp | x64 | MSYS2 CLANG64 clang/clang++ | o2-flto | MSYS2 CLANG64 DLLs | 15872 | 15.5 | cpp-msys-clang64-x64-o2-flto |
| cpp | x64 | LLVM clang/clang++ MSVC | o0 | DLL MSVC CRT | 229888 | 224.5 | cpp-llvm-clang-msvc-x64-o0 |
| cpp | x64 | LLVM clang/clang++ MSVC | o2 | DLL MSVC CRT | 224768 | 219.5 | cpp-llvm-clang-msvc-x64-o2 |
| cpp | x64 | LLVM clang/clang++ MSVC | os | DLL MSVC CRT | 223744 | 218.5 | cpp-llvm-clang-msvc-x64-os |
| cpp | x86 | LLVM clang/clang++ MSVC | o0 | DLL MSVC CRT | 184832 | 180.5 | cpp-llvm-clang-msvc-x86-o0 |
| cpp | x86 | LLVM clang/clang++ MSVC | o2 | DLL MSVC CRT | 179200 | 175.0 | cpp-llvm-clang-msvc-x86-o2 |
| cpp | x86 | LLVM clang/clang++ MSVC | os | DLL MSVC CRT | 178176 | 174.0 | cpp-llvm-clang-msvc-x86-os |
| cpp | x64 | LLVM clang/clang++ MSVC | o2-march-x86-64-v2 | DLL MSVC CRT | 224768 | 219.5 | cpp-llvm-clang-msvc-x64-o2-march-x86-64-v2 |
| cpp | x64 | LLVM clang/clang++ MSVC | o2-march-x86-64-v3 | DLL MSVC CRT | 224768 | 219.5 | cpp-llvm-clang-msvc-x64-o2-march-x86-64-v3 |
| cpp | x64 | LLVM clang/clang++ MSVC | o2-mtune-znver5 | DLL MSVC CRT | 224768 | 219.5 | cpp-llvm-clang-msvc-x64-o2-mtune-znver5 |
| cpp | x64 | LLVM clang/clang++ MSVC | o2-march-znver5 | DLL MSVC CRT | 224768 | 219.5 | cpp-llvm-clang-msvc-x64-o2-march-znver5 |
| cpp | x64 | LLVM clang/clang++ MSVC | o2-flto | DLL MSVC CRT | 224768 | 219.5 | cpp-llvm-clang-msvc-x64-o2-flto |
| cpp | x64 | Zig cc/c++ | o0 | Zig libc bundled | 920064 | 898.5 | cpp-zig-cc-x64-o0 |
| cpp | x64 | Zig cc/c++ | o2 | Zig libc bundled | 451072 | 440.5 | cpp-zig-cc-x64-o2 |
| cpp | x86 | Zig cc/c++ | o0 | Zig libc bundled | 917504 | 896.0 | cpp-zig-cc-x86-o0 |
| cpp | x86 | Zig cc/c++ | o2 | Zig libc bundled | 485376 | 474.0 | cpp-zig-cc-x86-o2 |
| cpp | x64 | Zig cc/c++ | o2-march-x86-64-v2 | Zig libc bundled | 450048 | 439.5 | cpp-zig-cc-x64-o2-march-x86-64-v2 |
| cpp | x64 | Zig cc/c++ | o2-march-x86-64-v3 | Zig libc bundled | 455680 | 445.0 | cpp-zig-cc-x64-o2-march-x86-64-v3 |
| cpp | x64 | Zig cc/c++ | o2-mtune-znver5 | Zig libc bundled | 460288 | 449.5 | cpp-zig-cc-x64-o2-mtune-znver5 |
| cpp | x64 | Zig cc/c++ | o2-march-znver5 | Zig libc bundled | 460288 | 449.5 | cpp-zig-cc-x64-o2-march-znver5 |
| rust | x64 | rustc GNULLVM | o0-panic-unwind | Rust std static + libunwind/UCRT DLLs | 268800 | 262.5 | rust-x64-gnullvm-o0-panic-unwind |
| rust | x64 | rustc GNULLVM | o0-panic-abort | Rust std static + libunwind/UCRT DLLs | 267264 | 261.0 | rust-x64-gnullvm-o0-panic-abort |
| rust | x64 | rustc GNULLVM | o3-panic-unwind | Rust std static + libunwind/UCRT DLLs | 268800 | 262.5 | rust-x64-gnullvm-o3-panic-unwind |
| rust | x64 | rustc GNULLVM | o3-panic-abort | Rust std static + libunwind/UCRT DLLs | 267264 | 261.0 | rust-x64-gnullvm-o3-panic-abort |
| rust | x64 | rustc GNULLVM | oz-panic-unwind | Rust std static + libunwind/UCRT DLLs | 268800 | 262.5 | rust-x64-gnullvm-oz-panic-unwind |
| rust | x64 | rustc GNULLVM | oz-panic-abort | Rust std static + libunwind/UCRT DLLs | 267264 | 261.0 | rust-x64-gnullvm-oz-panic-abort |
| rust | x64 | rustc GNULLVM | o3-panic-abort-target-cpu-x86-64-v2 | Rust std static + libunwind/UCRT DLLs | 267264 | 261.0 | rust-x64-gnullvm-o3-panic-abort-target-cpu-x86-64-v2 |
| rust | x64 | rustc GNULLVM | o3-panic-abort-target-cpu-x86-64-v3 | Rust std static + libunwind/UCRT DLLs | 267264 | 261.0 | rust-x64-gnullvm-o3-panic-abort-target-cpu-x86-64-v3 |
| rust | x64 | rustc GNULLVM | o3-panic-abort-target-cpu-native | Rust std static + libunwind/UCRT DLLs | 267264 | 261.0 | rust-x64-gnullvm-o3-panic-abort-target-cpu-native |
| rust | x64 | rustc GNULLVM | o3-panic-abort-lto-thin | Rust std static + libunwind/UCRT DLLs | 263680 | 257.5 | rust-x64-gnullvm-o3-panic-abort-lto-thin |
| rust | x64 | rustc GNU | o0-panic-unwind | Rust std static + Windows/UCRT DLLs | 836096 | 816.5 | rust-x64-gnu-o0-panic-unwind |
| rust | x64 | rustc GNU | o0-panic-abort | Rust std static + Windows/UCRT DLLs | 835584 | 816.0 | rust-x64-gnu-o0-panic-abort |
| rust | x64 | rustc GNU | o3-panic-unwind | Rust std static + Windows/UCRT DLLs | 836096 | 816.5 | rust-x64-gnu-o3-panic-unwind |
| rust | x64 | rustc GNU | o3-panic-abort | Rust std static + Windows/UCRT DLLs | 835584 | 816.0 | rust-x64-gnu-o3-panic-abort |
| rust | x64 | rustc GNU | oz-panic-unwind | Rust std static + Windows/UCRT DLLs | 836096 | 816.5 | rust-x64-gnu-oz-panic-unwind |
| rust | x64 | rustc GNU | oz-panic-abort | Rust std static + Windows/UCRT DLLs | 835584 | 816.0 | rust-x64-gnu-oz-panic-abort |
| rust | x64 | rustc GNU | o3-panic-abort-target-cpu-x86-64-v2 | Rust std static + Windows/UCRT DLLs | 835584 | 816.0 | rust-x64-gnu-o3-panic-abort-target-cpu-x86-64-v2 |
| rust | x64 | rustc GNU | o3-panic-abort-target-cpu-x86-64-v3 | Rust std static + Windows/UCRT DLLs | 835584 | 816.0 | rust-x64-gnu-o3-panic-abort-target-cpu-x86-64-v3 |
| rust | x64 | rustc GNU | o3-panic-abort-target-cpu-native | Rust std static + Windows/UCRT DLLs | 835584 | 816.0 | rust-x64-gnu-o3-panic-abort-target-cpu-native |
| rust | x64 | rustc GNU | o3-panic-abort-lto-thin | Rust std static + Windows/UCRT DLLs | 275968 | 269.5 | rust-x64-gnu-o3-panic-abort-lto-thin |
| rust | x64 | rustc MSVC | o0-panic-unwind | Rust std static + MSVC/UCRT DLLs | 129024 | 126.0 | rust-x64-msvc-o0-panic-unwind |
| rust | x64 | rustc MSVC | o0-panic-abort | Rust std static + MSVC/UCRT DLLs | 126464 | 123.5 | rust-x64-msvc-o0-panic-abort |
| rust | x64 | rustc MSVC | o3-panic-unwind | Rust std static + MSVC/UCRT DLLs | 125440 | 122.5 | rust-x64-msvc-o3-panic-unwind |
| rust | x64 | rustc MSVC | o3-panic-abort | Rust std static + MSVC/UCRT DLLs | 123904 | 121.0 | rust-x64-msvc-o3-panic-abort |
| rust | x64 | rustc MSVC | oz-panic-unwind | Rust std static + MSVC/UCRT DLLs | 125440 | 122.5 | rust-x64-msvc-oz-panic-unwind |
| rust | x64 | rustc MSVC | oz-panic-abort | Rust std static + MSVC/UCRT DLLs | 123904 | 121.0 | rust-x64-msvc-oz-panic-abort |
| rust | x64 | rustc MSVC | o3-panic-abort-target-cpu-x86-64-v2 | Rust std static + MSVC/UCRT DLLs | 123904 | 121.0 | rust-x64-msvc-o3-panic-abort-target-cpu-x86-64-v2 |
| rust | x64 | rustc MSVC | o3-panic-abort-target-cpu-x86-64-v3 | Rust std static + MSVC/UCRT DLLs | 123904 | 121.0 | rust-x64-msvc-o3-panic-abort-target-cpu-x86-64-v3 |
| rust | x64 | rustc MSVC | o3-panic-abort-target-cpu-native | Rust std static + MSVC/UCRT DLLs | 123904 | 121.0 | rust-x64-msvc-o3-panic-abort-target-cpu-native |
| rust | x64 | rustc MSVC | o3-panic-abort-lto-thin | Rust std static + MSVC/UCRT DLLs | 122368 | 119.5 | rust-x64-msvc-o3-panic-abort-lto-thin |
| rust | x86 | rustc MSVC | o0-panic-unwind | Rust std static + MSVC/UCRT DLLs | 113664 | 111.0 | rust-x86-msvc-o0-panic-unwind |
| rust | x86 | rustc MSVC | o0-panic-abort | Rust std static + MSVC/UCRT DLLs | 111616 | 109.0 | rust-x86-msvc-o0-panic-abort |
| rust | x86 | rustc MSVC | o3-panic-unwind | Rust std static + MSVC/UCRT DLLs | 112640 | 110.0 | rust-x86-msvc-o3-panic-unwind |
| rust | x86 | rustc MSVC | o3-panic-abort | Rust std static + MSVC/UCRT DLLs | 111104 | 108.5 | rust-x86-msvc-o3-panic-abort |
| rust | x86 | rustc MSVC | oz-panic-unwind | Rust std static + MSVC/UCRT DLLs | 112640 | 110.0 | rust-x86-msvc-oz-panic-unwind |
| rust | x86 | rustc MSVC | oz-panic-abort | Rust std static + MSVC/UCRT DLLs | 111104 | 108.5 | rust-x86-msvc-oz-panic-abort |
| go | x64 | Go gc | default | Go runtime bundled | 1667072 | 1628.0 | go-windows-amd64-default |
| go | x64 | Go gc | noopt | Go runtime bundled | 1718272 | 1678.0 | go-windows-amd64-noopt |
| go | x64 | Go gc | goamd64-v3 | Go runtime bundled | 1661440 | 1622.5 | go-windows-amd64-goamd64-v3 |
| go | x64 | Go gc | goamd64-v4 | Go runtime bundled | 1661440 | 1622.5 | go-windows-amd64-goamd64-v4 |
| go | x86 | Go gc | default | Go runtime bundled | 1552384 | 1516.0 | go-windows-386-default |
| go | x86 | Go gc | noopt | Go runtime bundled | 1595904 | 1558.5 | go-windows-386-noopt |
| zig | x64 | Zig build-exe | debug | Zig runtime bundled | 1119744 | 1093.5 | zig-x64-debug |
| zig | x86 | Zig build-exe | debug | Zig runtime bundled | 1174016 | 1146.5 | zig-x86-debug |
| zig | x64 | Zig build-exe | releasefast | Zig runtime bundled | 510976 | 499.0 | zig-x64-releasefast |
| zig | x86 | Zig build-exe | releasefast | Zig runtime bundled | 480768 | 469.5 | zig-x86-releasefast |
| zig | x64 | Zig build-exe | releasesmall | Zig runtime bundled | 433152 | 423.0 | zig-x64-releasesmall |
| zig | x86 | Zig build-exe | releasesmall | Zig runtime bundled | 406528 | 397.0 | zig-x86-releasesmall |
| csharp | x64 | .NET publish | framework release | .NET runtime external + app DLL | 162304 | 158.5 | csharp-framework-win-x64-release |
| csharp | x64 | .NET publish | readytorun singlefile release | .NET runtime external single-file | 180914 | 176.7 | csharp-readytorun-singlefile-win-x64-release |
| csharp | x64 | .NET publish | readytorun selfcontained singlefile release | .NET runtime bundled single-file | 83176755 | 81227.3 | csharp-readytorun-selfcontained-singlefile-win-x64-release |
| csharp | x86 | .NET publish | selfcontained release | .NET runtime files adjacent | 131584 | 128.5 | csharp-selfcontained-win-x86-release |
| csharp | x64 | .NET publish | nativeaot release | NativeAOT self-contained | 1105408 | 1079.5 | csharp-nativeaot-win-x64-release |
| csharp | x86 | .NET publish | nativeaot release | NativeAOT self-contained | 933888 | 912.0 | csharp-nativeaot-win-x86-release |
| pascal | x86 | Free Pascal | o1 | FPC runtime bundled | 34304 | 33.5 | pascal-fpc-win32-o1 |
| pascal | x86 | Free Pascal | o3 | FPC runtime bundled | 34304 | 33.5 | pascal-fpc-win32-o3 |
| d | x64 | DMD | x64 debug | D runtime bundled | 590336 | 576.5 | d-dmd-x64-debug |
| d | x64 | DMD | x64 release | D runtime bundled | 588800 | 575.0 | d-dmd-x64-release |
| d | x86 | DMD | x86 mscoff release | D runtime bundled | 505856 | 494.0 | d-dmd-x86-mscoff-release |
| assembly | x64 | NASM + lld-link | lld | WinAPI DLL imports | 1536 | 1.5 | assembly-nasm-x64-lld |
| assembly | x86 | NASM + lld-link | lld | WinAPI DLL imports | 3072 | 3.0 | assembly-nasm-x86-lld |
| assembly | x64 | MASM + link.exe | link | WinAPI DLL imports | 2560 | 2.5 | assembly-masm-x64-link |
| assembly | x86 | MASM + link.exe | link | WinAPI DLL imports | 3072 | 3.0 | assembly-masm-x86-link |
