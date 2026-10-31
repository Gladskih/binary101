"""Truth comes from Qt, source manifests and retained producer bytes, never binary101."""
import hashlib
import os
from pathlib import Path
import re
import shutil
import mmap
from image import file_offset, symbol_count
from model import digest


def canonical(path):
    return os.path.normcase(str(Path(path).resolve()))


def owned_files(report, module, image):
    if "error" in report or any("error" in entry for entry in report.get("files", [])):
        raise ValueError(f"Qt oracle failed: {report}")
    files = []
    for entry in report["files"]:
        if canonical(entry["module"]) != canonical(module):
            continue
        offset = file_offset(image, int(entry["relative"]))
        files.append({**entry, "offset": offset + (4 if entry["algorithm"] == 1 else 0)})
    return files


def arrays_from_cpp(path):
    text = re.sub(r"//[^\n]*", "", path.read_text(encoding="utf-8"))
    result = {}
    for name, body in re.findall(r"static const unsigned char qt_resource_(struct|name|data)\[\] = \{(.*?)\};", text, re.S):
        result[name] = bytes(int(value, 16) for value in re.findall(r"0x([0-9a-fA-F]+)", body))
    if set(result) != {"struct", "name", "data"}:
        raise ValueError("Cannot independently identify all rcc producer arrays")
    return result


def unused_files(directory, image, resource, report):
    arrays = arrays_from_cpp(directory / resource["cpp"])
    with image.open("rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        positions = retained_arrays(data, arrays)
    qres = (directory / resource["qres"]).read_bytes()
    data_start = int.from_bytes(qres[12:16], "big")
    files = []
    for entry in report["files"]:
        if canonical(entry["module"]) != canonical(directory / resource["qres"]):
            continue
        relative = int(entry["relative"]) - data_start
        size = int(entry["storedSize"])
        if relative < 0 or relative + size > len(arrays["data"]):
            raise ValueError("Qt consumer pointer exceeds retained data array")
        offset = positions["data"] + relative
        files.append({**entry, "offset": offset + (4 if entry["algorithm"] == 1 else 0)})
    return files


def retained_arrays(data, arrays):
    positions = {name: data.find(value) for name, value in arrays.items()}
    if any(offset < 0 for offset in positions.values()):
        raise ValueError("Unused arrays were eliminated or transformed")
    if data.find(arrays["data"], positions["data"] + 1) >= 0:
        raise ValueError("Ambiguous unused data-array location")
    return positions


def confirm_expected(resource, files):
    expected = {(entry["path"], entry["sha256"], entry.get("locale", "C")) for entry in resource["expected"]}
    actual = {(entry["path"], entry["sha256"], entry["locale"]) for entry in files if entry["path"].startswith(resource["prefix"] + "/")}
    if expected != actual:
        raise ValueError(f"Qt/source manifest disagreement: {expected ^ actual}")


def label_image(job, directory, image, target, prepared, oracle):
    files = owned_files(oracle["registered"], target, image)
    files = select_variants(files, prepared)
    bundles = []
    for resource in prepared["resources"]:
        if prepared["negative"]:
            continue
        if job["family"] == "unused":
            assert_unregistered(resource, files)
            files.extend(select_variants(unused_files(directory, image, resource, oracle[resource["qres"]]), prepared))
        confirm_expected(resource, files)
        offsets = [entry["offset"] for entry in files if entry["path"].startswith(resource["prefix"] + "/")]
        bundles.append({"prefix": resource["prefix"], "payloadOffsets": offsets})
    prefixes = [resource["prefix"] + "/" for resource in prepared["resources"]]
    builtin = [entry for entry in files if not any(entry["path"].startswith(prefix) for prefix in prefixes)]
    return files, bundles, "unknown" if builtin else "verified"


def assert_unregistered(resource, files):
    if any(entry["path"].startswith(resource["prefix"] + "/") for entry in files):
        raise ValueError("Unused tables unexpectedly registered")


def select_variants(files, prepared):
    expected = {(entry["path"], entry.get("locale", "C")) for resource in prepared["resources"] for entry in resource["expected"]}
    known_paths = {key[0] for key in expected}
    selected, seen = [], set()
    for entry in files:
        if entry["path"] in known_paths:
            if (entry["path"], entry["locale"]) not in expected:
                continue
            identity = (entry["path"], entry["locale"])
        else:
            identity = (entry["path"], entry["offset"], entry["sha256"])
        if identity not in seen:
            selected.append(entry)
            seen.add(identity)
    return selected


def label_variants(job, sdk, directory, target, stripped, prepared, oracle, output):
    if symbol_count(target) == 0 or symbol_count(stripped) != 0:
        raise ValueError("Symbol/stripped pair does not satisfy the claimed symbol state")
    labels = []
    for variant, image in (("symbols", target), ("stripped", stripped)):
        files, bundles, bundle_status = label_image(job, directory, image, target, prepared, oracle)
        negative_evidence = negative_bytes(directory, image, prepared)
        if variant == "stripped":
            verify_retained_bytes(target, image, files)
        identity = hashlib.sha256((job["id"] + "-" + variant).encode()).hexdigest()[:24]
        destination = output / "samples" / identity / target.name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(image, destination)
        labels.append({"schemaVersion": 1, "id": identity, "path": str(destination), "sha256": digest(destination),
                       "status": "verified", "files": files, "bundles": bundles, "bundleStatus": bundle_status,
                       "caseId": job["id"], "family": job["family"], "split": job["split"], "variant": variant,
                       "format": sdk["format"], "registration": prepared["registration"],
                       "producer": job, "negativeEvidence": negative_evidence, "evidence": image_evidence(job)})
    return labels


def image_evidence(job):
    if job["family"] == "plain":
        return ["Qt-free source/control", "link command", "symbol/strip state"]
    return ["Qt runtime ownership", "Qt/source SHA256 agreement", "retained resource bytes"]


def negative_bytes(directory, image, prepared):
    if not prepared["negative"]:
        return []
    evidence = []
    with image.open("rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        for name in prepared["sourceFiles"]:
            text = (directory / name).read_text(encoding="utf-8")
            declarations = re.findall(r"static const volatile unsigned char (\w+)\[\][^=]*=\s*\{([^}]*)\}", text)
            if not declarations:
                raise ValueError("Negative source contains no independently verifiable decoy")
            for symbol, numbers in declarations:
                value = bytes(int(number) for number in numbers.split(",") if number.strip())
                offset = data.find(value)
                if not value or offset < 0:
                    raise ValueError("Compiled negative decoy was eliminated or changed")
                evidence.append({"source": name, "symbol": symbol, "offset": offset,
                                 "size": len(value), "sha256": hashlib.sha256(value).hexdigest()})
    return evidence


def verify_retained_bytes(target, stripped, files):
    for entry in files:
        if canonical(entry["module"]) != canonical(target):
            continue
        raw = int(entry["relative"])
        before = file_offset(target, raw)
        after = file_offset(stripped, raw)
        size = int(entry["storedSize"])
        if stored_bytes(target, before, size) != stored_bytes(stripped, after, size):
            raise ValueError("Stripping changed stored resource bytes")


def stored_bytes(path, offset, size):
    with path.open("rb") as stream:
        stream.seek(offset)
        data = stream.read(size)
    if len(data) != size:
        raise ValueError("Stored resource exceeds final file")
    return data
