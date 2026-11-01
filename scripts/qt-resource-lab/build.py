"""Build real Qt targets; capture commands, Qt's oracle and stripped twins."""
import json
from pathlib import Path
import shutil
from model import PROFILES, write_json
from process import run
from sources import prepare
from truth import label_variants


def project(directory, sdk, job, prepared):
    compiler = sdk[job["compiler"]]
    flags = PROFILES[job["profile"]]
    link = link_flags(job)
    lines = ["QT = core", "CONFIG += release console c++17", "CONFIG -= debug app_bundle strip",
             "QMAKE_LFLAGS_RELEASE =",
             "TARGET = sample", f"QMAKE_CXX = {compiler}", f"QMAKE_LINK = {compiler}",
             "QMAKE_CXXFLAGS_RELEASE = " + " ".join(flags),
             "QMAKE_LFLAGS += " + " ".join(link) + " -Wl,-Map,link.map",
             "SOURCES += oracle.cpp " + " ".join(prepared["sourceFiles"])]
    if job.get("family") == "plain":
        lines[0] = "QT ="
    else:
        lines += ["DEFINES += LAB_QT"]
    if sdk["format"] == "PE":
        lines += ["QMAKE_LFLAGS += -Wl,--no-insert-timestamp"]
    if job["target"] == "library":
        lines += ["TEMPLATE = lib", "CONFIG += dll", "CONFIG -= staticlib", "VERSION ="]
    else:
        lines += ["TEMPLATE = app", "SOURCES += entry.cpp"]
        if sdk["format"] == "ELF":
            lines += ["QMAKE_LFLAGS += -Wl,--export-dynamic"]
    if prepared["negative"]:
        lines += ["DEFINES += LAB_DECOY"]
    if job["compiler"] == "clang":
        lines += ["QMAKE_CXXFLAGS -= -fno-keep-inline-dllexport -Wa,-mbig-obj"]
    (directory / "sample.pro").write_text("\n".join(lines) + "\n", encoding="utf-8")


def link_flags(job):
    if job["profile"] == "O3-sections":
        return ["-Wl,--sort-section=name"]
    if job["profile"] != "LTO":
        return []
    return ["-flto", "-fuse-ld=lld"] if job["compiler"] == "clang" else ["-flto"]


def target_path(directory, sdk, job):
    if job["target"] == "library":
        name = "sample.dll" if sdk["format"] == "PE" else "libsample.so"
    else:
        name = "sample.exe" if sdk["format"] == "PE" else "sample"
    candidates = (directory / name, directory / "release" / name)
    return next(path for path in candidates if path.is_file())


def invoke_oracle(directory, sdk, job, target, records):
    commands = [str(target)]
    if job["target"] == "library":
        loader = directory / ("loader.exe" if sdk["format"] == "PE" else "loader")
        command = [sdk[job["compiler"]], "-O2", "loader.cpp", "-o", str(loader)]
        if sdk["format"] == "ELF":
            command += ["-ldl"]
        records.append(run(command, directory, directory / "loader-build.log", environment=sdk["environment"]))
        commands = [str(loader), str(target)]
    output = {}
    for key, arguments in [("registered", [])] + [(r["qres"], [str(directory / r["qres"])]) for r in records_resources(directory)]:
        log = directory / f"oracle-{key}.json"
        records.append(run([*commands, *arguments], directory, log, timeout=30, environment=sdk["environment"]))
        output[key] = json.loads(log.read_text(encoding="utf-8"))
    return output


def records_resources(directory):
    return json.loads((directory / "prepared.json").read_text(encoding="utf-8"))["resources"]


def build_one(job, sdk, directory, output):
    prepared = prepare(directory, sdk, job)
    write_json(directory / "prepared.json", prepared)
    project(directory, sdk, job, prepared)
    records = prepared["commands"]
    records.append(run([sdk["qmake"], "sample.pro"], directory, directory / "qmake.log", environment=sdk["environment"]))
    records.append(run([sdk["make"], "-j1"], directory, directory / "build.log", timeout=180, environment=sdk["environment"]))
    target = target_path(directory, sdk, job)
    oracle = invoke_oracle(directory, sdk, job, target, records)
    stripped = directory / ("stripped" + target.suffix)
    shutil.copyfile(target, stripped)
    records.append(run([sdk["strip"], "--strip-all", str(stripped)], directory, directory / "strip.log", environment=sdk["environment"]))
    write_json(directory / "oracle.json", oracle)
    labels = label_variants(job, sdk, directory, target, stripped, prepared, oracle, output)
    record = {"schemaVersion": 1, "job": job, "sdk": {k: v for k, v in sdk.items() if k != "environment"},
              "status": "built", "commands": records, "labels": labels,
              "cpuSeconds": sum(r["cpuSeconds"] or 0 for r in records),
              "commandWallSeconds": sum(r["wallSeconds"] for r in records),
              "peakBytes": max(r["peakBytes"] or 0 for r in records)}
    write_json(directory / "result.json", record)
    return record
