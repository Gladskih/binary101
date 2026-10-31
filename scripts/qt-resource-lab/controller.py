"""Resumable, budgeted cross-platform corpus generation with a pilot gate."""
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
from model import digest, job_for, pilot_schedule, read_jsonl, schedule, write_json

WORKER = Path(__file__).with_name("worker.py")
PYTHON = os.environ.get("QT_LAB_WINDOWS_PYTHON", "C:/msys64/ucrt64/bin/python.exe")


def linux_path(path):
    value = str(Path(path).resolve()).replace("\\", "/")
    if len(value) < 3 or value[1:3] != ":/":
        raise ValueError("Windows controller expects an absolute drive path")
    return "/mnt/" + value[0].lower() + value[2:]


def windows_path(path):
    return path[5].upper() + ":" + path[6:] if path.startswith("/mnt/") else path


def doctor(output):
    records = []
    for command in ([PYTHON, str(WORKER), "--doctor"],
                    ["wsl.exe", "--", "python3", linux_path(WORKER), "--doctor"]):
        result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", timeout=60)
        records.append(json.loads(result.stdout) if result.returncode == 0 else {"error": result.stderr})
    record = {"schemaVersion": 1, "platforms": records,
              "sdks": [sdk for platform in records for sdk in platform.get("sdks", [])]}
    write_json(output / "doctor.json", record)
    return record


def execute(job, sdk, output):
    root = output / "jobs" / job["id"]
    result_path = root / "result.json"
    if result_path.is_file():
        saved = json.loads(result_path.read_text(encoding="utf-8"))
        if valid_cached(saved, sdk):
            return {**saved, "resumed": True}
    return rebuild(job, sdk, output)


def rebuild(job, sdk, output):
    root = output / "jobs" / job["id"]
    result_path = root / "result.json"
    directory = str(root / "native")
    result_path.unlink(missing_ok=True)
    specification = {"job": job, "sdk": sdk, "directory": directory, "recipeSha256": recipe_hash(),
                     "output": str(output), "result": str(result_path)}
    if sdk["format"] == "ELF":
        specification.update(directory=f"{sdk['buildRoot']}/{output.name}/{job['id']}",
                             output=linux_path(output), result=linux_path(result_path))
    job_path = root / "job.json"
    write_json(job_path, specification)
    command = [PYTHON, str(WORKER), "--job", str(job_path)]
    if sdk["format"] == "ELF":
        command = ["wsl.exe", "--", "python3", linux_path(WORKER), "--job", linux_path(job_path)]
    with (root / "worker.log").open("wb") as log:
        subprocess.run(command, stdout=log, stderr=log, timeout=900)
    if not result_path.is_file():
        return {"status": "failed", "job": job, "error": "Worker exited without a result"}
    result = json.loads(result_path.read_text(encoding="utf-8"))
    for label in result.get("labels", []):
        label["path"] = windows_path(label["path"])
    return result


def valid_cached(saved, sdk):
    identity_matches = (saved.get("recipeSha256") == recipe_hash()
                        and saved.get("kitSha256") == sdk["fingerprint"] and saved["status"] == "built")
    compiler_matches = saved.get("sdk", {}).get("compilerVersions") == sdk.get("compilerVersions")
    return identity_matches and compiler_matches and all(valid_published(label) for label in saved.get("labels", []))


def valid_published(label):
    path = Path(windows_path(label["path"]))
    return path.is_file() and digest(path) == label["sha256"]


def recipe_hash():
    value = hashlib.sha256()
    dependencies = {"build.py", "sources.py", "truth.py", "image.py", "process.py",
                    "windows_job.py", "sdk.py", "worker.py", "model.py"}
    for path in sorted(WORKER.parent.iterdir()):
        if path.name in dependencies or path.suffix == ".cpp":
            value.update(path.name.encode())
            value.update(path.read_bytes())
    return value.hexdigest()


def smoke_schedule(rows, sdks):
    selected = []
    for format_name in ("ELF", "PE"):
        sdk = next(s for s in sdks if s["format"] == format_name and s["linkage"] == "shared")
        for family, target in (("basic", "exe"), ("bad-hash", "library")):
            selected.append(job_for(rows, sdk["id"], "gcc", target, "O0", family))
    return selected


def build(output, mode, workers, minutes, seed, limit=None):
    kits = doctor(output)["sdks"]
    if not kits:
        raise ValueError("No complete Qt SDK")
    rows = schedule(kits, seed)
    if mode == "smoke":
        rows = smoke_schedule(rows, kits)
    elif mode == "pilot":
        rows = pilot_schedule(rows)
    else:
        require_pilot(output, kits)
    rows = rows[:limit]
    write_json(output / f"{mode}-schedule.json", rows)
    write_json(output / "unsupported-cells.json", unsupported_cells(kits))
    executor = execute if mode == "build" else rebuild
    result = run_batch(rows, kits, output, workers, minutes, executor)
    write_json(output / f"{mode}-run.json", result)
    export_corpus(output)
    return result


def unsupported_cells(kits):
    return [{"sdk": sdk["id"], "algorithm": algorithm, "reason": capability["stderr"]}
            for sdk in kits for algorithm, capability in sdk["compression"].items() if not capability["supported"]]


def require_pilot(output, kits):
    gate = output / "pilot-gate.json"
    if not gate.is_file():
        raise ValueError("Run and verify the pilot before a bulk run")
    record = json.loads(gate.read_text(encoding="utf-8"))
    if not valid_pilot_identity(record, kits):
        raise ValueError("Pilot gate failed or SDK inventory changed")
    labels = {row["id"]: row["sha256"] for row in read_jsonl(output / "labels.jsonl")}
    if any(labels.get(identity) != checksum for identity, checksum in record["pilotSamples"].items()):
        raise ValueError("Pilot inputs changed since validation")


def valid_pilot_identity(record, kits):
    return all((record.get("passed"), record["sdkIds"] == sorted(sdk["id"] for sdk in kits),
                record["recipeSha256"] == recipe_hash(),
                record["sdkFingerprints"] == {sdk["id"]: sdk["fingerprint"] for sdk in kits},
                record.get("sdkCompilerVersions") == {sdk["id"]: sdk.get("compilerVersions") for sdk in kits}))


def run_batch(rows, kits, output, workers, minutes, executor):
    started = time.monotonic()
    deadline = started + minutes * 60
    by_id = {sdk["id"]: sdk for sdk in kits}
    completed, pending = [], {}
    remaining = iter(rows)
    reason = "completed"
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        while True:
            while len(pending) < workers and time.monotonic() < deadline and reason == "completed":
                row = next(remaining, None)
                if row is None:
                    break
                pending[pool.submit(executor, row, by_id[row["sdk"]], output)] = row
            if not pending:
                break
            done, _ = concurrent.futures.wait(pending, return_when=concurrent.futures.FIRST_COMPLETED)
            for future in done:
                row = pending.pop(future)
                completed.append(completed_result(future, row))
            reason = stop_reason(completed, started, workers, deadline, reason)
            write_json(output / "progress.json", summarize(completed, started, workers, reason))
    return summarize(completed, started, workers, reason)


def completed_result(future, row):
    try:
        return future.result()
    except Exception as error:
        return {"status": "failed", "job": row, "error": str(error)}


def stop_reason(completed, started, workers, deadline, previous):
    if previous != "completed":
        return previous
    if time.monotonic() >= deadline:
        return "budget"
    pressure = pressure_reason(completed[-8:])
    return pressure or preparation_failure(completed) or cpu_reason(completed, started, workers) or previous


def preparation_failure(completed):
    from collections import Counter
    failures = [record for record in completed if record["status"] != "built"]
    classes = Counter(Path(record.get("log", "unknown")).name for record in failures)
    return "repeated-preparation-failure" if any(count >= 2 for count in classes.values()) else None


def pressure_reason(recent):
    failures = [record for record in recent if record["status"] != "built"]
    if len(failures) >= 3:
        return "systematic-failures"
    if any(record.get("peakBytes", 0) > 1400 * 1024 * 1024 for record in recent):
        return "memory-pressure"
    return None


def cpu_reason(completed, started, workers):
    fresh = [record for record in completed if not record.get("resumed")]
    if len(fresh) >= max(16, workers * 4):
        cpu = sum(record.get("cpuSeconds", 0) for record in fresh)
        if cpu / max(1, time.monotonic() - started) / workers < 0.5:
            return "not-cpu-bound"
    return None


def summarize(records, started, workers, reason):
    fresh = [record for record in records if not record.get("resumed")]
    elapsed = time.monotonic() - started
    return {"status": reason, "attempted": len(records), "built": sum(r["status"] == "built" for r in records),
            "resumed": len(records) - len(fresh), "wallSeconds": elapsed, "workers": workers,
            "cpuSeconds": sum(r.get("cpuSeconds", 0) for r in fresh),
            "cpuCapacityFraction": sum(r.get("cpuSeconds", 0) for r in fresh) / max(1, elapsed) / workers,
            "failures": [{"id": r["job"]["id"], "error": r["error"]} for r in records if r["status"] != "built"]}


def export_corpus(output):
    labels = []
    for result in sorted((output / "jobs").glob("*/result.json")):
        record = json.loads(result.read_text(encoding="utf-8"))
        if record.get("recipeSha256") == recipe_hash():
            labels.extend(record.get("labels", []))
    real = output / "real-labels.json"
    if real.is_file():
        labels.extend(json.loads(real.read_text(encoding="utf-8")))
    for label in labels:
        label["path"] = windows_path(label["path"])
    with (output / "labels.jsonl").open("w", encoding="utf-8") as gold, (output / "samples.jsonl").open("w", encoding="utf-8") as inputs:
        for label in labels:
            gold.write(json.dumps(label, ensure_ascii=False) + "\n")
            inputs.write(json.dumps({key: label[key] for key in ("id", "path", "sha256")}) + "\n")
