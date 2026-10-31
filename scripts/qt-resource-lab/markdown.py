"""A short human-readable result alongside complete machine-readable reports."""
import json


def write_markdown(output, summary):
    run = summary["buildRuns"].get("build", summary["buildRuns"].get("pilot", {}))
    totals = summary["totals"]
    denominator = summary["denominators"]
    lines = ["# Qt RCC corpus experiment", "",
             f"Samples: **{summary['samples']}**; unique SHA256: **{summary['uniqueSha256']}**.",
             f"Complete evaluated inputs: {denominator['evaluatedCompleteInputs']}; "
             f"positive: {denominator['positiveInputs']}; negative: {denominator['negativeInputs']}.",
             f"Ground-truth inventories: `{json.dumps(summary['truthCounts'], sort_keys=True)}`.", "",
             "## Build run", "",
             f"State: `{run.get('status', 'not-run')}`; jobs: {run.get('built', 0)}/{run.get('attempted', 0)}; "
             f"resumed: {run.get('resumed', 0)}.",
             f"Wall time: {run.get('wallSeconds', 0) / 60:.2f} min; "
             f"child CPU: {run.get('cpuSeconds', 0) / 60:.2f} CPU-min; "
             f"worker CPU capacity used: {run.get('cpuCapacityFraction', 0):.1%}.", "",
             "## Baseline scanner", "",
             "Counts include verified known bundles from partially labelled real modules; "
             "unknown remainder is unscored.", "",
             "| Metric | Count |", "| --- | ---: |"]
    for key in ("tp", "fp", "fn", "duplicates", "content_mismatches", "metadata_mismatches",
                "bundle_tp", "bundle_fp", "bundle_fn", "file_tp", "file_fp", "file_fn"):
        lines.append(f"| {key} | {totals.get(key, 0)} |")
    lines += ["", f"Scanner statuses: `{json.dumps(summary['scannerStatuses'], sort_keys=True)}`.", "",
              "## Coverage and limitations", "", *sdk_lines(output), "",
              "The matrix is x86-64, Qt 5/6, GCC/Clang, executable/shared-library targets, "
              "shared/static Qt, six optimization profiles, and symbol/stripped pairs.",
              "MSVC and whole-Qt LTO are not established. Build variants are correlated; "
              "zero observed false positives is not a zero-FP guarantee.",
              "No new production detection rule was fitted or enabled in this stage.", "",
              "See `summary.json` for configuration/split results, `labels.jsonl` for evidence, "
              "`predictions.jsonl` for raw replies, and `repro/` for small observed discrepancies."]
    (output / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def sdk_lines(output):
    doctor = json.loads((output / "doctor.json").read_text(encoding="utf-8"))
    lines = [f"- `{sdk['id']}`; Qt-internal LTO: `{sdk['qtLto']}`." for sdk in doctor["sdks"]]
    path = output / "unsupported-cells.json"
    unsupported = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else []
    lines.extend(f"- Unsupported: `{cell['sdk']}` / `{cell['algorithm']}`." for cell in unsupported)
    return lines
