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


def registered_label(output, sdk, executable, image, registrations):
    root = output / "real-oracle" / digest(image)
    root.mkdir(parents=True, exist_ok=True)
    offsets = [file_offset(image, value) for group in registrations for value in group]
    files, bundles, evidence = [], [], []
    for index, registration in enumerate(registrations):
        qres = root / f"bundle{index}.rcc"
        qres.write_bytes(container_for(image, registration, offsets))
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
            entry = {**item, "offset": file_offset(image, registration[2]) + int(item["relative"]) - 24}
            entry["offset"] += 4 if item["algorithm"] == 1 else 0
            files.append(entry)
            group.append(entry["offset"])
        bundles.append({"payloadOffsets": group, "registrationRvas": registration})
    label = copy_real(output, image)
    label.update(status="partial", files=files, bundles=bundles, bundleStatus="verified",
                 evidence=["SHA256-pinned shipping module", "externally supplied registration arguments", "independent Qt consumer"],
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


def read_real_inputs(output):
    entries = json.loads((output / "real-inputs.json").read_text(encoding="utf-8"))
    if not isinstance(entries, list):
        raise ValueError("real-inputs.json must contain an array")
    return [validate_input(entry, output) for entry in entries]


def validate_input(entry, output):
    if not isinstance(entry, dict) or not isinstance(entry.get("path"), str) or not entry["path"]:
        raise ValueError("Each real input needs a path")
    image = (output / entry["path"]).resolve()
    if not image.is_file():
        raise FileNotFoundError(image)
    registrations = entry.get("registrations", [])
    if not isinstance(registrations, list) or not all(valid_registration(group) for group in registrations):
        raise ValueError("Registrations must be arrays of three PE RVAs: tree, names, data")
    expected = entry.get("sha256")
    if (registrations or expected is not None) and expected != digest(image):
        raise ValueError("Real input SHA256 must match; registrations require a pinned SHA256")
    return {**entry, "path": image, "registrations": registrations}


def valid_registration(group):
    # PE/COFF section 3.3: RVAs are unsigned 32-bit image-relative addresses.
    # https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
    return isinstance(group, list) and len(group) == 3 and all(
        type(value) is int and 0 <= value <= 0xffffffff for value in group)


def real_corpus(output):
    inputs = read_real_inputs(output)
    labels = [copy_real(output, entry["path"]) for entry in inputs if not entry["registrations"]]
    registered = [entry for entry in inputs if entry["registrations"]]
    if registered:
        sdk = next((s for s in discover()["sdks"] if s["major"] == 5 and s["linkage"] == "shared"), None)
        if sdk is None:
            raise ValueError("Registered inputs require a shared Qt 5 SDK")
        executable = consumer(output, sdk)
        labels.extend(registered_label(output, sdk, executable, entry["path"], entry["registrations"])
                      for entry in registered)
    write_json(output / "real-labels.json", labels)
    from controller import export_corpus
    export_corpus(output)
    return {"realFiles": len(labels), "confirmedFiles": sum(len(r["files"]) for r in labels),
            "unknownModules": sum(r["status"] == "unknown" for r in labels), "scope": "Known bundles only; other real content remains unknown"}
