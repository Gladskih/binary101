"""Discover actual Qt kits. qmake supplies the kit's real transitive link dependencies."""
import os
from pathlib import Path
import shutil
import subprocess
import hashlib
import json
import tempfile


def query(command, env=None):
    environment = os.environ.copy()
    environment.update(env or {})
    return subprocess.check_output(command, text=True, encoding="utf-8", errors="replace",
                                   env=environment, timeout=30).strip()


def discover():
    candidates = windows_candidates() if os.name == "nt" else linux_candidates()
    found, absent = [], []
    for major, linkage, qmake in candidates:
        if not Path(qmake).is_file():
            absent.append({"major": major, "linkage": linkage, "qmake": qmake})
            continue
        found.append(make_kit(major, linkage, qmake))
    return {"schemaVersion": 1, "sdks": found, "unavailable": absent,
            "msvc": "not-covered: no matching MSVC Qt SDK configured"}


def rcc_path(values):
    name = "rcc.exe" if os.name == "nt" else "rcc"
    candidates = (Path(values[key]) / name for key in
                  ("QT_HOST_LIBEXECS", "QT_INSTALL_LIBEXECS", "QT_INSTALL_BINS") if key in values)
    return next((str(path) for path in candidates if path.is_file()), None)


def make_kit(major, linkage, qmake):
    environment = environment_for(qmake)
    values = dict(line.split(":", 1) for line in query([qmake, "-query"], environment).splitlines() if ":" in line)
    rcc = rcc_path(values)
    tools = tool_commands(environment)
    return {"id": f"{'pe' if os.name == 'nt' else 'elf'}-qt{values['QT_VERSION']}-{linkage}",
                      "major": major, "qtVersion": values["QT_VERSION"], "linkage": linkage,
                      "qmake": qmake, "rcc": rcc, "format": "PE" if os.name == "nt" else "ELF",
                      "buildRoot": str(Path.home() / ".cache/binary101-qt-resource-lab"),
                      **tools,
                      "environment": environment, "qtLto": qt_lto(qmake, major),
                      "fingerprint": kit_fingerprint(values, major, qmake, rcc),
                      "compression": probe_compression(rcc, environment),
                      "compilerVersions": {kind: version_for(tools[kind], environment) for kind in ("gcc", "clang")}}


def tool_commands(environment):
    suffix = ".exe" if os.name == "nt" else ""
    names = {"make": "mingw32-make" if os.name == "nt" else "make",
             "strip": "strip", "gcc": "g++", "clang": "clang++"}
    return {kind: find_tool(name + suffix, environment) for kind, name in names.items()}


def probe_compression(rcc, environment):
    env = os.environ.copy()
    env.update(environment)
    results = {}
    with tempfile.TemporaryDirectory(prefix="qt-lab-capability-") as temporary:
        directory = Path(temporary)
        (directory / "input.txt").write_text("Qt compression probe " * 100)
        (directory / "probe.qrc").write_text('<RCC><qresource><file>input.txt</file></qresource></RCC>')
        for algorithm in ("none", "zlib", "zstd"):
            command = [rcc, "--binary", "--compress-algo", algorithm, "--threshold", "0",
                       "probe.qrc", "-o", "probe.rcc"]
            result = subprocess.run(command, cwd=directory, env=env, capture_output=True, timeout=30)
            results[algorithm] = {"supported": result.returncode == 0,
                                  "stderr": result.stderr.decode("utf-8", errors="replace")[:512]}
    return results


def find_tool(name, environment):
    return shutil.which(name, path=environment["PATH"])


def version_for(tool, environment):
    return query([tool, "--version"], environment).splitlines()[0] if tool else "unavailable"


def qt_lto(qmake, major):
    manifest = Path(qmake).parents[2] / f"build-qt{major}/sdk-build.json"
    if manifest.is_file():
        return json.loads(manifest.read_text())["qtLto"]
    return "not-established"


def kit_fingerprint(values, major, qmake, rcc):
    paths = [Path(qmake), Path(rcc)]
    library = Path(values["QT_INSTALL_LIBS"])
    paths.extend(library.glob(f"*Qt{major}Core.*"))
    paths.extend(Path(values["QT_INSTALL_BINS"]).glob(f"Qt{major}Core.dll"))
    checksum = hashlib.sha256()
    for path in sorted({path.resolve() for path in paths if path.is_file()}):
        checksum.update(str(path).encode())
        with path.open("rb") as stream:
            checksum.update(hashlib.file_digest(stream, "sha256").digest())
    return checksum.hexdigest()


def environment_for(qmake):
    env = {"PATH": os.environ["PATH"]}
    if os.name == "nt":
        prefix = Path(qmake).parents[1]
        root = prefix.parent if prefix.name.endswith("-static") else prefix
        env["PATH"] = str(root / "bin") + os.pathsep + str(Path(qmake).parent) + os.pathsep + env["PATH"]
    env.update(SOURCE_DATE_EPOCH="1700000000", QT_QPA_PLATFORM="offscreen", LC_ALL="C.UTF-8")
    return env


def windows_candidates():
    root = Path(os.environ.get("QT_LAB_UCRT64", "C:/msys64/ucrt64"))
    return [(major, linkage, str(root / (f"qt{major}-static/bin/qmake.exe" if linkage == "static"
                                       else f"bin/qmake{'6' if major == 6 else '-qt5'}.exe")))
            for major in (5, 6) for linkage in ("shared", "static")]


def linux_candidates():
    cache = Path(os.environ.get("QT_LAB_SDK_CACHE", Path.home() / ".cache/binary101-qt-rcc-sdks"))
    return [(5, "shared", "/usr/lib/qt5/bin/qmake"), (6, "shared", "/usr/bin/qmake6"),
            (5, "static", str(cache / "qt5/bin/qmake")),
            (6, "static", str(cache / "qt6/bin/qmake"))]
