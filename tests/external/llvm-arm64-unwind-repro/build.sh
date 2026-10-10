#!/bin/sh
set -eu
cd "$(dirname "$0")"
mkdir -p out
"${CLANG:-clang}" --target=aarch64-pc-windows-msvc -c chained.s -o out/chained.obj
"${CLANG:-clang}" --target=aarch64-pc-windows-msvc -c chained.s \
    -Wa,-defsym,PACKED_CONTROL=1 -o out/packed.obj
"${CLANG:-clang}" --target=aarch64-pc-windows-msvc -c directory.s -o out/directory.obj
for name in chained packed directory; do
    "${LLD_LINK:-lld-link}" /entry:main /subsystem:console /nodefaultlib /machine:arm64 \
        "/out:out/$name.exe" "out/$name.obj"
done
"${LLD_LINK:-lld-link}" /entry:main /subsystem:console /nodefaultlib /machine:arm64 \
    /merge:.tail=.pdata /out:out/merged.exe out/directory.obj
