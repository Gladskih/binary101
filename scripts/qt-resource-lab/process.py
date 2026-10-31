"""Bounded commands with descendant CPU/RSS accounting; no shell interpolation."""
import os
from pathlib import Path
import subprocess
import time
from contextlib import nullcontext


def run(command, directory, log, timeout=120, environment=None, input_path=None, error_path=None):
    started = time.monotonic()
    env = os.environ.copy()
    env.update(environment or {})
    if os.name == "nt":
        from windows_job import run_job
        result = run_job(command, directory, log, timeout, env, input_path, error_path)
    else:
        result = run_unix(command, directory, log, timeout, env, input_path, error_path)
    result.update(command=command, cwd=str(directory), wallSeconds=time.monotonic() - started)
    if result["exitCode"] != 0:
        raise CommandFailure(result, log)
    return result


class CommandFailure(Exception):
    def __init__(self, result, log):
        self.result = result
        self.log = str(log)
        super().__init__(f"Command exited {result['exitCode']}; see {log}")


def run_unix(command, directory, log, timeout, env, input_path, error_path):
    import resource
    def limit_memory():
        resource.setrlimit(resource.RLIMIT_AS, (1536 * 1024 * 1024, 1536 * 1024 * 1024))
    accounting = str(log) + ".time"
    wrapped = ["/usr/bin/time", "-f", "%U %S %M", "-o", accounting, *command]
    with Path(log).open("wb") as stream, open(input_path or os.devnull, "rb") as inputs, \
            (Path(error_path).open("wb") if error_path else nullcontext(stream)) as errors:
        child = subprocess.Popen(wrapped, cwd=directory, stdout=stream, stderr=errors, stdin=inputs,
                                 env=env, start_new_session=True, preexec_fn=limit_memory)
        try:
            code = child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            import signal
            os.killpg(child.pid, signal.SIGKILL)
            child.wait()
            return {"exitCode": -1, "status": "timeout", "cpuSeconds": None, "peakBytes": None}
    lines = Path(accounting).read_text().splitlines()
    user, system, peak = map(float, lines[-1].split())
    return {"exitCode": code, "status": "ok" if code == 0 else "error",
            "cpuSeconds": user + system, "peakBytes": int(peak * 1024)}
