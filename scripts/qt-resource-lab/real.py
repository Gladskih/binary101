"""Shipping binaries: independently confirmed bundles and explicitly unknown inventories."""
import json
from pathlib import Path
import shutil
import struct
from build import build_one, target_path
from image import file_offset, image_regions
from model import digest, write_json
from process import run
from sdk import discover

WIDGETS = Path("C:/Program Files/LogiOptionsPlus/Qt5Widgets.dll")
WIDGETS_SHA = "f1335f713a4873bb9e28112b7b34c119afa7278d12a969cbd91766d3f52cc414"
# Manually audited with LLVM objdump: calls at RVA 14ae/14ee through
# thunk 338c99 -> IAT 33b140 -> Qt5Core!qRegisterResourceData.
# Windows x64 arguments: ECX=3, RDX=tree, R8=names, R9=data.
REGISTRATIONS = ((0x3da6d0, 0x3d8800, 0x386460), (0x3dbad0, 0x3dba60, 0x3db650))


def consumer(output, sdk):
    directory = output / "real-oracle/native"
    job = {"id": "real-oracle", "family": "empty", "seed": 101, "profile": "O2",
           "compiler": "gcc", "target": "exe", "split": "development", "sdk": sdk["id"]}
    build_one(job, sdk, directory, output / "real-oracle")
    return target_path(directory, sdk, job)


def container_for(image, registration, all_offsets):
    tree, names, data = registration
    regions = image_regions(image)
    content = image.read_bytes()
    parts = {}
    for key, address in (("tree", tree), ("names", names), ("data", data)):
        start = file_offset(image, address)
        _, raw, size = next(region for region in regions if region[1] <= start < region[1] + region[2])
        end = min([raw + size, *(value for value in all_offsets if value > start)])
        parts[key] = content[start:end]
    header = struct.pack(">4sIIIII", b"qres", 3, 24 + len(parts["data"]) + len(parts["names"]),
                         24, 24 + len(parts["data"]), 5)
    return header + parts["data"] + parts["names"] + parts["tree"]


def widgets_label(output, sdk, executable):
    root = output / "real-oracle/widgets"
    root.mkdir(parents=True, exist_ok=True)
    offsets = [file_offset(WIDGETS, value) for group in REGISTRATIONS for value in group]
    files, bundles, evidence = [], [], []
    for index, registration in enumerate(REGISTRATIONS):
        qres = root / f"bundle{index}.rcc"
        qres.write_bytes(container_for(WIDGETS, registration, offsets))
        log = root / f"qt-consumer{index}.json"
        evidence.append(run([str(executable), str(qres)], root, log, environment=sdk["environment"]))
        report = json.loads(log.read_text(encoding="utf-8"))
        if "error" in report:
            raise ValueError(report)
        group = []
        seen = set()
        for item in report["files"]:
            if Path(item["module"]).resolve() != qres.resolve():
                continue
            identity = (item["path"], item["relative"])
            if identity in seen:
                continue
            seen.add(identity)
            entry = {**item, "offset": file_offset(WIDGETS, registration[2]) + int(item["relative"]) - 24}
            entry["offset"] += 4 if item["algorithm"] == 1 else 0
            files.append(entry)
            group.append(entry["offset"])
        bundles.append({"payloadOffsets": group, "registrationRvas": registration})
    label = copy_real(output, WIDGETS)
    label.update(status="partial", files=files, bundles=bundles, bundleStatus="verified",
                 evidence=["SHA256-pinned shipping module", "LLVM-audited registration arguments", "independent Qt consumer"],
                 registration="confirmed", oracleCommands=evidence)
    return label


def copy_real(output, source):
    identity = "real-" + source.name + "-" + digest(source)[:12]
    destination = output / "samples" / identity / source.name
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    return {"schemaVersion": 1, "id": identity, "path": str(destination), "sha256": digest(source),
            "origin": str(source), "status": "unknown", "files": [], "bundles": [],
            "bundleStatus": "unknown", "family": "shipping-" + source.parent.name,
            "split": "holdout", "variant": "shipping", "format": "PE", "registration": "unknown"}


def real_corpus(output):
    sdk = next(s for s in discover()["sdks"] if s["major"] == 5 and s["linkage"] == "shared")
    executable = consumer(output, sdk)
    labels = []
    if WIDGETS.is_file() and digest(WIDGETS) == WIDGETS_SHA:
        labels.append(widgets_label(output, sdk, executable))
    candidates = (WIDGETS, WIDGETS.with_name("Qt5Gui.dll"), WIDGETS.with_name("Qt5Core.dll"),
                  Path("C:/Program Files/VideoLAN/VLC/plugins/gui/libqt_plugin.dll"),
                  Path("C:/Program Files/LogiOptionsPlus/PlugInInstallerUtility.exe"),
                  Path("C:/msys64/ucrt64/qt5-static/bin/assistant.exe"),
                  Path("C:/msys64/ucrt64/qt5-static/bin/designer.exe"),
                  Path("C:/msys64/ucrt64/share/qt6/bin/qtdiag.exe"))
    append_existing(labels, output, candidates)
    write_json(output / "real-labels.json", labels)
    from controller import export_corpus
    export_corpus(output)
    return {"realFiles": len(labels), "confirmedFiles": sum(len(r["files"]) for r in labels),
            "unknownModules": sum(r["status"] == "unknown" for r in labels), "scope": "Known bundles only; other real content remains unknown"}


def append_existing(labels, output, candidates):
    for path in candidates:
        if path.is_file() and not any(label["origin"] == str(path) for label in labels):
            labels.append(copy_real(output, path))
