"""Explicit research CLI; never runs as an ordinary npm test hook."""
import argparse
import json
from pathlib import Path
import sys
from controller import build, doctor
from evaluate import evaluate_files
from model import write_json
from gate import gate
from report import report
from lock import corpus_lock


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("doctor", "smoke", "pilot", "counterexamples", "build", "scan", "evaluate", "report", "gate", "selftest", "real", "mutate-evaluator"))
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--workers", type=int, default=4, choices=range(1, 9))
    parser.add_argument("--minutes", type=float, default=60)
    parser.add_argument("--seed", type=int, default=101)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--scanner", type=Path)
    parser.add_argument("--scanner-revision", default="")
    parser.add_argument("--timeout", type=float, default=30)
    return parser.parse_args()


def main():
    args = arguments()
    output = args.out.resolve()
    if output.is_relative_to(Path(__file__).resolve().parents[2]):
        raise ValueError("Corpus output must be outside the repository checkout")
    output.mkdir(parents=True, exist_ok=True)
    with corpus_lock(output):
        result = dispatch(args, output)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if result.get("failures") or result.get("passed") is False:
        raise SystemExit(1)



def doctor_brief(output):
    result = doctor(output)
    return {"sdks": [{k: sdk[k] for k in ("id", "format", "gcc", "clang", "rcc")}
                     for sdk in result["sdks"]]}


def evaluate_report(output):
    write_json(output / "evaluation.json", evaluate_files(output / "labels.jsonl", output / "predictions.jsonl"))
    return report(output)


def dispatch(args, output):
    from selftest import selftest
    from real import real_corpus
    from scan import scan_corpus
    from mutation import mutate_evaluator
    actions = {"doctor": lambda: doctor_brief(output), "gate": lambda: gate(output),
               "selftest": lambda: selftest(output), "real": lambda: real_corpus(output),
               "mutate-evaluator": lambda: mutate_evaluator(output),
               "scan": lambda: scan_corpus(output, args.scanner, args.workers, args.timeout, args.scanner_revision),
               "evaluate": lambda: evaluate_report(output), "report": lambda: report(output)}
    if args.command in ("smoke", "pilot", "counterexamples", "build"):
        return build(output, args.command, args.workers, args.minutes, args.seed, args.limit)
    return actions[args.command]()


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
