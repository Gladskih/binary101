#!/bin/sh
# Run in Linux/WSL with Qt 5/6 tools and GLib development tools installed.
# Payloads are original test data. Binary layouts are emitted by upstream tools.
set -eu
target="$(cd "$(dirname "$0")/.." && pwd)/generated/embedded-resource-oracles"
mkdir -p "$target"
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
cd "$temporary"
printf 'Qt and GLib resource oracle.' > plain.txt
python3 -c 'print("Binary101 resource oracle " * 50, end="")' > message.txt
printf '%s' '<gresources><gresource prefix="/org/binary101"><file>plain.txt</file><file compressed="true">message.txt</file></gresource></gresources>' > resources.xml
printf '%s' '<RCC><qresource prefix="/org/binary101"><file>plain.txt</file><file>message.txt</file></qresource></RCC>' > resources.qrc
glib-compile-resources resources.xml --target="$target/oracle.gresource"
export SOURCE_DATE_EPOCH=1700000000
/usr/lib/qt5/bin/rcc --binary --format-version 1 resources.qrc -o "$target/oracle-v1.rcc"
/usr/lib/qt5/bin/rcc --binary --format-version 2 resources.qrc -o "$target/oracle-v2.rcc"
/usr/lib/qt6/libexec/rcc --binary --compress-algo zstd --format-version 3 resources.qrc -o "$target/oracle-v3.rcc"
/usr/lib/qt6/libexec/rcc resources.qrc -o qrc.cpp
cat > runtime.cpp <<'CPP'
// Registration stubs make a linkable analysis fixture; this fixture is never executed.
bool qRegisterResourceData(int, const unsigned char *, const unsigned char *, const unsigned char *) { return true; }
bool qUnregisterResourceData(int, const unsigned char *, const unsigned char *, const unsigned char *) { return true; }
extern const unsigned char qt_resourceFeatureZstd = 0;
unsigned char qResourceFeatureZstd() { return 0; }
CPP
python3 - "$target" <<'PY'
import pathlib, sys
target = pathlib.Path(sys.argv[1])
with open('payloads.c', 'w') as output:
    for name, filename, section in [
        ('glib_named', 'oracle.gresource', '.gresource.oracle'),
        ('glib_ordinary', 'oracle.gresource', '.rdata'),
        ('qt_package', 'oracle-v3.rcc', '.rdata')
    ]:
        data = (target / filename).read_bytes()
        output.write('const unsigned char ' + name + '[] __attribute__((used, section("' + section + '"))) = {')
        output.write(','.join(str(byte) for byte in data))
        output.write('};\n')
PY
g++ -O2 -fPIC -c qrc.cpp -o "$target/qt-arrays.o"
g++ -O2 -shared -fPIC qrc.cpp runtime.cpp payloads.c -o "$target/qt-glib.so"
x86_64-w64-mingw32-g++ -O2 -shared -Wl,--no-insert-timestamp qrc.cpp runtime.cpp payloads.c -o "$target/qt-glib.dll"
