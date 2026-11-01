"""Versioned corpus records and deterministic, family-separated build schedules."""
import hashlib
import itertools
import json
from pathlib import Path
from counterexample_assets import FAMILIES as COUNTEREXAMPLES

FAMILIES = ("basic", "localized", "compressed", "zstd", "shared", "multiple", "unused",
            "empty", "plain", "magic", "bad-hash", "bad-link", "bad-size", "mixed", *COUNTEREXAMPLES)
PROFILES = {"O0": ["-O0"], "O2": ["-O2"], "O3": ["-O3"], "Os": ["-Os"],
            "Oz": ["-Oz"], "LTO": ["-O3", "-flto"], "O3-sections": ["-O3", "-fdata-sections"]}
HOLDOUT = frozenset(("multiple", "bad-link", "mixed", "small-sets", "opaque"))


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read_jsonl(path):
    with Path(path).open(encoding="utf-8") as stream:
        return [json.loads(line) for line in stream if line.strip()]


def write_json(path, record):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)


def schedule(sdks, seed):
    rows = []
    dimensions = (sdks, ("gcc", "clang"), ("exe", "library"), PROFILES, FAMILIES)
    for sdk, compiler, target, profile, family in itertools.product(*dimensions):
        if not supported_family(sdk, family):
            continue
        identity = f"{sdk['id']}-{compiler}-{target}-{profile}-{family}-{seed}"
        rows.append({"id": identity, "sdk": sdk["id"], "compiler": compiler,
                     "format": sdk.get("format", "test"),
                     "rccVersion": 3 if family == "zstd" else 1 + (seed + list(PROFILES).index(profile)) % 3,
                     "target": target, "profile": profile, "family": family, "seed": seed,
                     "split": "holdout" if family in HOLDOUT else "development"})
    return sorted(rows, key=lambda row: hashlib.sha256(row["id"].encode()).digest())


def supported_family(sdk, family):
    algorithm = {"zstd": "zstd", "compressed": "zlib", "compressed-sizes": "zlib"}.get(family, "none")
    return sdk.get("compression", {}).get(algorithm, {"supported": True})["supported"]


def pilot_schedule(rows):
    selected = []
    groups = sorted({(r["sdk"], r["target"]) for r in rows})
    for index, (sdk, target) in enumerate(groups):
        for family in ("basic", "bad-hash"):
            selected.append(job_for(rows, sdk, "gcc" if index % 2 else "clang", target,
                                    "O0" if index % 2 else "LTO", family))
    selected.extend(coverage_examples(rows))
    return list({row["id"]: row for row in selected}.values())


def coverage_examples(rows):
    selected = []
    for format_name in sorted({r["format"] for r in rows}):
        sdk = next(r["sdk"] for r in rows if r["format"] == format_name)
        for compiler, profile in itertools.product(("gcc", "clang"), PROFILES):
            selected.append(job_for(rows, sdk, compiler, "exe", profile, "basic"))
        for family in FAMILIES:
            family_sdk = next(r["sdk"] for r in rows if r["format"] == format_name and r["family"] == family)
            selected.append(job_for(rows, family_sdk, "gcc", "library", "LTO", family))
    return selected


def job_for(rows, sdk, compiler, target, profile, family):
    identity = (sdk, compiler, target, profile, family)
    return next(row for row in rows if tuple(row[key] for key in ("sdk", "compiler", "target", "profile", "family")) == identity)


def counterexample_schedule(rows, sdks):
    # Validate each family on both formats/Qt majors before multiplying variants.
    kits = [sdk for sdk in sdks if sdk["linkage"] == "shared"]
    ordinary = [job_for(rows, sdk["id"], compiler, "exe", profile, family)
            for family, profile, compiler in itertools.product((*COUNTEREXAMPLES, "bad-size", "bad-hash", "empty"),
                                                               ("O3", "LTO"), ("gcc", "clang"))
            for sdk in kits if supported_family(sdk, family)]
    return ordinary + [job_for(rows, sdk["id"], compiler, "exe", "O3-sections", "multiple")
                       for sdk, compiler in itertools.product(kits, ("gcc", "clang"))]
