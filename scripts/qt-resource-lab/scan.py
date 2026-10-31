"""Scanner isolation: only id/path on stdin, bounded child job, cached by input and implementation."""
import concurrent.futures
import hashlib
import json
from pathlib import Path
import subprocess
from model import digest, read_jsonl, write_json
from process import CommandFailure, run

REPO = Path(__file__).resolve().parents[2]


def baseline_command():
    import shutil
    return [shutil.which("node"), "--import", "tsx",
            str(REPO / "scripts/qt-resource-lab-scanner.ts")]


def fingerprint(command, revision=""):
    value = hashlib.sha256(json.dumps([command, revision]).encode())
    for argument in command:
        path = Path(argument)
        if path.is_file():
            value.update(digest(path).encode())
    value.update(subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO))
    value.update(subprocess.check_output(["git", "diff", "--", "analyzers"], cwd=REPO))
    # Candidate analyzers often start as untracked files. HEAD/diff alone misses them.
    for path in sorted((REPO / "analyzers").rglob("*.ts")):
        value.update(str(path.relative_to(REPO)).encode())
        value.update(digest(path).encode())
    return value.hexdigest()


def scan_one(sample, command, root, timeout):
    root.mkdir(parents=True, exist_ok=True)
    cached = root / "result.json"
    if cached.is_file():
        saved = json.loads(cached.read_text(encoding="utf-8"))
        if saved.get("inputSha256") == sample["sha256"] and saved.get("status") == "ok":
            return saved
    return scan_fresh(sample, command, root, timeout)


def scan_fresh(sample, command, root, timeout):
    root.mkdir(parents=True, exist_ok=True)
    cached = root / "result.json"
    if digest(sample["path"]) != sample["sha256"]:
        return {"id": sample["id"], "status": "error", "error": "Input SHA256 changed"}
    request = root / "request.jsonl"
    request.write_text(json.dumps({"id": sample["id"], "path": sample["path"]}) + "\n", encoding="utf-8")
    log = root / "stdout.jsonl"
    try:
        metrics = run(command, REPO, log, timeout=timeout, input_path=request, error_path=root / "stderr.log")
        result = parse_reply(log, sample["id"])
        result["metrics"] = metrics
    except CommandFailure as error:
        result = {"id": sample["id"], "status": error.result["status"], "error": str(error)}
    except Exception as error:
        result = {"id": sample["id"], "status": "error", "error": str(error)}
    result["inputSha256"] = sample["sha256"]
    write_json(cached, result)
    return result


def parse_reply(log, identity):
    if log.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("Scanner output exceeds 16 MiB")
    rows = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(rows) != 1 or rows[0].get("id") != identity:
        raise ValueError("Expected exactly one response with matching id")
    return validate_reply(rows[0])


def validate_reply(record):
    if record.get("status") == "ok":
        if not isinstance(record.get("bundles"), list):
            raise ValueError("Missing bundles array")
        for bundle in record["bundles"]:
            if not isinstance(bundle.get("files"), list):
                raise ValueError("Missing bundle files array")
            for item in bundle["files"]:
                validate_file(item)
    elif record.get("status") not in ("error", "timeout", "unsupported"):
        raise ValueError("Invalid scanner status")
    return record


def validate_file(item):
    if not isinstance(item.get("path"), str) or not isinstance(item.get("sha256"), str):
        raise ValueError("Expected file path and SHA256 strings")
    if not isinstance(item.get("offset"), int) or item["offset"] < 0:
        raise ValueError("Expected nonnegative absolute payload offset")


def scan_corpus(output, scanner_config, workers, timeout, revision=""):
    command = json.loads(scanner_config.read_text(encoding="utf-8")) if scanner_config else baseline_command()
    if not isinstance(command, list) or not command or not all(isinstance(arg, str) for arg in command):
        raise ValueError("Scanner config must be a nonempty JSON argv array")
    identity = fingerprint(command, revision)
    samples = read_jsonl(output / "samples.jsonl")
    root = output / "scans" / identity
    execute = scanner_executor(scanner_config, revision)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(execute, sample, command, root / sample["id"], timeout) for sample in samples]
        with (output / "predictions.jsonl").open("w", encoding="utf-8") as stream:
            for future in concurrent.futures.as_completed(futures):
                stream.write(json.dumps(future.result(), ensure_ascii=False) + "\n")
                stream.flush()
    return {"samples": len(samples), "scannerSha256": identity, "command": command,
            "revision": revision, "cacheEnabled": execute is scan_one}


def scanner_executor(scanner_config, revision):
    return scan_one if scanner_config is None or revision else scan_fresh
