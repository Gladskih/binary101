"""One native-platform build worker. Input and output are immutable job JSON."""
import argparse
import json
from pathlib import Path
import traceback
from build import build_one
from model import write_json
from process import CommandFailure
from sdk import discover


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--doctor", action="store_true")
    parser.add_argument("--job")
    arguments = parser.parse_args()
    if arguments.doctor:
        print(json.dumps(discover(), ensure_ascii=False))
        return
    specification = json.loads(Path(arguments.job).read_text(encoding="utf-8"))
    result_path = Path(specification["result"])
    directory = Path(specification["directory"])
    output = Path(specification["output"])
    try:
        directory.mkdir(parents=True, exist_ok=True)
        result = build_one(specification["job"], specification["sdk"], directory, output)
    except Exception as error:
        result = {"status": "failed", "job": specification["job"], "error": str(error),
                  "traceback": traceback.format_exc()}
        if isinstance(error, CommandFailure):
            result.update(failedCommand=error.result, log=error.log)
    result["recipeSha256"] = specification["recipeSha256"]
    result["kitSha256"] = specification["sdk"]["fingerprint"]
    write_json(result_path, result)


if __name__ == "__main__":
    main()
