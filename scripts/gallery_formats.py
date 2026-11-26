from pathlib import Path
from shutil import copyfile
from subprocess import run
from tempfile import TemporaryDirectory


def build_macho(source, output):
    with TemporaryDirectory() as work:
        slices = []
        for arch in ("x86_64", "arm64"):
            obj = Path(work) / f"hello-{arch}.o"
            run(["clang", f"--target={arch}-apple-macos11", "-c", "-O2", "-o", obj,
                 source / "hello-macho.c"], check=True)
            slices.append(obj)
        run(["llvm-lipo", "-create", *slices, "-output", output / "hello-universal.o"],
            check=True)


def build_archives(source, output):
    with TemporaryDirectory() as work:
        archive = Path(work) / "hello-solid.7z"
        copyfile(source / "hello.txt", Path(work) / "hello.txt")
        copyfile(source / "hello-wasm.c", Path(work) / "hello-wasm.c")
        run(["7z", "a", "-t7z", "-m0=LZMA2", "-ms=on", archive, "hello.txt", "hello-wasm.c"],
            cwd=work, check=True)
        copyfile(archive, output / archive.name)
    run(["xorriso", "-as", "mkisofs", "-V", "BINARY101_GALLERY", "-J", "-graft-points",
         "-o", output / "hello-joliet.iso", f"docs/Greetings.txt={source / 'hello.txt'}",
         f"code/hello.wasm={output / 'hello.wasm'}"], check=True)


def build_extra_formats(source, output):
    run(["clang", "--target=aarch64-pc-windows-msvc", "-fuse-ld=lld", "-nostdlib", "-shared",
         "-ffreestanding", "-O2", "-march=armv8-a+crc+crypto", "-Wl,/noentry", "-Wl,/noimplib",
         "-o", output / "hello-arm64.dll", source / "hello-arm64.c"], check=True)
    run(["upx", "-f", "--lzma", "-o", output / "hello-upx.exe", output / "hello-msvc-x64.exe"],
        check=True)
    run(["makensis", "-V2", f"-DOUTPUT_FILE={output / 'hello-nsis.exe'}", "hello.nsi"],
        cwd=source, check=True)
    build_macho(source, output)
    build_archives(source, output)
