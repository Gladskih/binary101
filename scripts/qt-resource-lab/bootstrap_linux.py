"""Optional native static Qt SDK preparation; outside the measured corpus batch."""
import argparse
import json
from pathlib import Path
import tarfile
import urllib.request
from model import digest, write_json
from process import run

SOURCES = {
    5: ("5.15.18", "https://github.com/qt/qtbase/archive/refs/tags/v5.15.18-lts-lgpl.tar.gz"),
    6: ("6.10.2", "https://download.qt.io/official_releases/qt/6.10/6.10.2/submodules/qtbase-everywhere-src-6.10.2.tar.xz")}


def download(url, destination):
    temporary = destination.with_suffix(".part")
    with urllib.request.urlopen(url, timeout=60) as response, temporary.open("wb") as stream:
        while block := response.read(1024 * 1024):
            stream.write(block)
    temporary.replace(destination)


def bootstrap(major, cache, jobs):
    version, url = SOURCES[major]
    root = cache / f"build-qt{major}"
    root.mkdir(parents=True, exist_ok=True)
    source, checksum = source_tree(root, version, url)
    directory = root / "build"
    directory.mkdir(exist_ok=True)
    prefix = cache / f"qt{major}"
    flags = ["-opensource", "-confirm-license", "-static", "-release", "-prefix", str(prefix),
             "-nomake", "examples", "-nomake", "tests", "-no-gui", "-no-widgets",
             "-no-dbus", "-no-icu", "-no-openssl", "-no-feature-concurrent",
             "-no-feature-network", "-no-feature-sql", "-no-feature-xml"]
    records = []
    if major == 5 and not (source / "include/QtCore/qglobal.h").is_file():
        records.append(run(["perl", str(source / "bin/syncqt.pl"), "-version", version,
                            "-outdir", str(source), str(source)], root, root / "syncqt.log", timeout=120))
    if not (directory / ("Makefile" if major == 5 else "build.ninja")).is_file():
        records.append(run([str(source / "configure"), *flags], directory, root / "configure.log", timeout=600))
    command = ["make", f"-j{jobs}"] if major == 5 else ["cmake", "--build", ".", "--parallel", str(jobs)]
    records.append(run(command, directory, root / "build.log", timeout=3600))
    install = ["make", "install"] if major == 5 else ["cmake", "--install", "."]
    records.append(run(install, directory, root / "install.log", timeout=300))
    write_json(root / "sdk-build.json", {"major": major, "version": version, "qtLto": "disabled",
                                         "sourceSha256": checksum, "commands": records})
    print(json.dumps({"prefix": str(prefix), "version": version, "status": "installed"}))


def source_tree(root, version, url):
    archive = root / "source.tar"
    pin = root / "source.json"
    if not archive.is_file():
        download(url, archive)
    checksum = digest(archive)
    if pin.is_file() and json.loads(pin.read_text())["sha256"] != checksum:
        raise ValueError("Cached source SHA256 differs from the frozen source pin")
    write_json(pin, {"version": version, "url": url, "sha256": checksum})
    source = root / "source"
    if not source.is_dir():
        unpack = root / "unpacked"
        unpack.mkdir(exist_ok=True)
        with tarfile.open(archive) as package:
            package.extractall(unpack, filter="data")
        next(path for path in unpack.iterdir() if path.is_dir()).rename(source)
    return source, checksum


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--major", type=int, choices=(5, 6), required=True)
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--cache", type=Path, default=Path.home() / ".cache/binary101-qt-rcc-sdks")
    args = parser.parse_args()
    bootstrap(args.major, args.cache, args.jobs)
