#!/bin/sh
# Run from the repository root. Generated binaries stay in ignored scan-results.
set -eu
mkdir -p scan-results/sanitizers
for compiler in gcc clang; do
  for sanitizer in address thread undefined leak; do
    "$compiler" -O0 -g -fsanitize="$sanitizer" samples/sanitizers/access.c \
      -o "scan-results/sanitizers/$compiler-$sanitizer"
  done
  "$compiler" -O0 samples/sanitizers/access.c -o "scan-results/sanitizers/$compiler-plain"
  "$compiler" -O0 -fsanitize=undefined -fsanitize-trap=all samples/sanitizers/access.c \
    -o "scan-results/sanitizers/$compiler-trap"
done
for sanitizer in memory dataflow; do
  clang -O0 -g -fsanitize="$sanitizer" samples/sanitizers/access.c \
    -o "scan-results/sanitizers/clang-$sanitizer"
done
clang -O0 -fsanitize=undefined -fsanitize-minimal-runtime samples/sanitizers/access.c \
  -o scan-results/sanitizers/clang-ubsan-minimal
# No AArch64 runtime or sysroot is needed to inspect instrumented object references.
clang -target aarch64-linux-gnu -O0 -fsanitize=hwaddress -c samples/sanitizers/access.c \
  -o scan-results/sanitizers/clang-hwasan.o
clang++ -O0 -fsanitize=realtime samples/sanitizers/realtime.cpp \
  -o scan-results/sanitizers/clang-realtime
clang -O0 -fsanitize=type samples/sanitizers/alias.c -o scan-results/sanitizers/clang-type
clang -O0 -fsanitize-coverage=trace-pc-guard -c samples/sanitizers/access.c \
  -o scan-results/sanitizers/clang-coverage.o
gcc -O0 samples/sanitizers/strings.c -o scan-results/sanitizers/gcc-strings
strip --strip-all -o scan-results/sanitizers/gcc-address-stripped scan-results/sanitizers/gcc-address
strip --strip-all -o scan-results/sanitizers/clang-address-stripped scan-results/sanitizers/clang-address
for binary in scan-results/sanitizers/gcc-* scan-results/sanitizers/clang-*; do
  printf '\n%s\n' "$binary"
  readelf -d "$binary" 2>/dev/null | grep NEEDED || true
  nm "$binary" | grep -E '__(asan|tsan|ubsan|lsan|msan|dfsan|hwasan)_' | head -8 || true
done
