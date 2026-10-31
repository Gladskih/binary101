"""Run SDK-independent conformance tests before allowing expensive corpus generation."""
from pathlib import Path
import unittest
from model import write_json


def selftest(output):
    suite = unittest.defaultTestLoader.discover(str(Path(__file__).parent / "tests"))
    with (output / "selftest.log").open("w", encoding="utf-8") as stream:
        result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
    record = {"passed": result.wasSuccessful(), "tests": result.testsRun,
              "failures": len(result.failures), "errors": len(result.errors)}
    write_json(output / "selftest.json", record)
    return record
