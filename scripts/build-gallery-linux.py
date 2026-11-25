from contextlib import closing
import os
from pathlib import Path
from shutil import copyfile
import sqlite3
import subprocess
from zipfile import ZIP_DEFLATED, ZipFile

from gallery_media import build_media


def build_sqlite(output):
    with closing(sqlite3.connect(":memory:")) as database:
        database.executescript("""
            CREATE TABLE greeting (id INTEGER PRIMARY KEY, language TEXT, message TEXT);
            CREATE UNIQUE INDEX greeting_language ON greeting(language);
            INSERT INTO greeting (language, message) VALUES
                ('en', 'Hello, world!'), ('de', 'Hallo, Welt!'), ('fr', 'Bonjour le monde !');
        """)
        output.write_bytes(database.serialize())


def main():
    root = Path(__file__).resolve().parent.parent
    output = root / "generated/gallery"
    output.mkdir(parents=True, exist_ok=True)
    source = root / "samples/pe-disassembly"
    subprocess.run(["gcc", "-O2", "-g", "-fPIE", "-pie", "-Wl,-z,relro,-z,now",
                    f"-fdebug-prefix-map={root}=.",
                    "-o", output / "hello-gcc-x64.elf", source / "c/hello.c"], check=True)
    subprocess.run(["go", "build", "-trimpath", "-ldflags=-s -w",
                    "-o", output / "hello-go-arm64.elf", source / "go/hello.go"],
                   env={**os.environ, "GOOS": "linux", "GOARCH": "arm64", "CGO_ENABLED": "0"},
                   check=True)
    go_root = Path(subprocess.check_output(["go", "env", "GOROOT"], text=True).strip())
    copyfile(go_root / "LICENSE", output / "go-linux-license.txt")
    wasm_source = root / "samples/gallery/hello-wasm.c"
    wasm = output / "hello.wasm"
    subprocess.run(["clang", "--target=wasm32", "-O2", "-nostdlib", "-Wl,--no-entry",
                    "-Wl,--export-memory", "-Wl,--export=greet", "-o", wasm, wasm_source],
                   check=True)
    with ZipFile(output / "hello-samples.zip", "w") as archive:
        archive.write(wasm_source, wasm_source.name, compress_type=ZIP_DEFLATED)
        archive.write(wasm, wasm.name)
    build_sqlite(output / "hello.sqlite")
    build_media(output)


if __name__ == "__main__":
    main()
