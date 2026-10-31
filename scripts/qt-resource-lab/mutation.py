"""Small explicit mutation audit of evaluator decisions; survivors are reported, never hidden."""
import ast
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from model import write_json

ROOT = Path(__file__).parent


def mutations(tree):
    for index, node in enumerate(ast.walk(tree)):
        comparison = comparison_mutation(node)
        if comparison:
            yield index, "comparison", comparison
        binary = binary_mutation(node)
        if binary:
            yield index, "binary", binary
        if isinstance(node, ast.Constant) and type(node.value) is int and node.value in (0, 1):
            yield index, "integer", 1 - node.value
        if isinstance(node, ast.BoolOp):
            yield index, "boolean", ast.Or if isinstance(node.op, ast.And) else ast.And


def comparison_mutation(node):
    if isinstance(node, ast.Compare) and len(node.ops) == 1:
        opposites = {ast.Eq: ast.NotEq, ast.NotEq: ast.Eq, ast.In: ast.NotIn, ast.NotIn: ast.In}
        return opposites.get(type(node.ops[0]))
    return None


def binary_mutation(node):
    if isinstance(node, ast.BinOp):
        return {ast.BitAnd: ast.BitOr, ast.Sub: ast.Add}.get(type(node.op))
    return None


def apply_mutation(tree, index, kind, replacement):
    changed = deepcopy(tree)
    node = list(ast.walk(changed))[index]
    if kind == "comparison":
        node.ops[0] = replacement()
    elif kind == "integer":
        node.value = replacement
    else:
        node.op = replacement()
    return ast.unparse(changed)


def check_mutant(source, directory):
    (directory / "evaluate.py").write_text(source, encoding="utf-8")
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONPATH"] = str(directory) + os.pathsep + str(ROOT)
    command = [sys.executable, "-m", "unittest", "discover", "-s", str(ROOT / "tests"), "-p", "test_evaluate.py"]
    try:
        result = subprocess.run(command, cwd=directory, env=environment, capture_output=True, timeout=15)
        return "survived" if result.returncode == 0 else "killed"
    except subprocess.TimeoutExpired:
        return "timeout"


def mutate_evaluator(output):
    tree = ast.parse((ROOT / "evaluate.py").read_text(encoding="utf-8"))
    records = []
    with tempfile.TemporaryDirectory(prefix="qt-lab-mutation-") as temporary:
        directory = Path(temporary)
        if check_mutant(ast.unparse(tree), directory) != "survived":
            raise ValueError("Unmutated evaluator tests fail; mutation results would be invalid")
        for index, kind, replacement in mutations(tree):
            status = check_mutant(apply_mutation(tree, index, kind, replacement), directory)
            records.append({"node": index, "line": list(ast.walk(tree))[index].lineno, "kind": kind, "status": status})
    result = {"module": "evaluate.py", "mutants": records,
              "killed": sum(row["status"] == "killed" for row in records),
              "survived": sum(row["status"] == "survived" for row in records),
              "timeout": sum(row["status"] == "timeout" for row in records)}
    write_json(output / "evaluator-mutation.json", result)
    return {key: value for key, value in result.items() if key != "mutants"}
