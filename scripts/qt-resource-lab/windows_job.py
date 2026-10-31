"""Windows Job Object accounting includes native compiler/linker descendants."""
import ctypes as ct
from ctypes import wintypes as wt
import msvcrt
from pathlib import Path
import subprocess
from contextlib import nullcontext


class Startup(ct.Structure):
    _fields_ = [("cb", wt.DWORD), ("reserved", wt.LPWSTR), ("desktop", wt.LPWSTR),
                ("title", wt.LPWSTR), ("x", wt.DWORD), ("y", wt.DWORD),
                ("width", wt.DWORD), ("height", wt.DWORD), ("charsX", wt.DWORD),
                ("charsY", wt.DWORD), ("fill", wt.DWORD), ("flags", wt.DWORD),
                ("show", wt.WORD), ("reservedSize", wt.WORD), ("reservedBytes", ct.c_void_p),
                ("stdin", wt.HANDLE), ("stdout", wt.HANDLE), ("stderr", wt.HANDLE)]


class ProcessInfo(ct.Structure):
    _fields_ = [("process", wt.HANDLE), ("thread", wt.HANDLE),
                ("processId", wt.DWORD), ("threadId", wt.DWORD)]


class Accounting(ct.Structure):
    _fields_ = [("user", ct.c_int64), ("kernel", ct.c_int64),
                ("periodUser", ct.c_int64), ("periodKernel", ct.c_int64),
                ("faults", wt.DWORD), ("total", wt.DWORD),
                ("active", wt.DWORD), ("terminated", wt.DWORD)]


class BasicLimit(ct.Structure):
    _fields_ = [("processTime", ct.c_int64), ("jobTime", ct.c_int64), ("flags", wt.DWORD),
                ("minWorkingSet", ct.c_size_t), ("maxWorkingSet", ct.c_size_t),
                ("active", wt.DWORD), ("affinity", ct.c_size_t),
                ("priority", wt.DWORD), ("scheduling", wt.DWORD)]


class ExtendedLimit(ct.Structure):
    _fields_ = [("basic", BasicLimit), ("io", ct.c_uint64 * 6),
                ("processMemory", ct.c_size_t), ("jobMemory", ct.c_size_t),
                ("peakProcessMemory", ct.c_size_t), ("peakJobMemory", ct.c_size_t)]


def kernel_api():
    kernel = ct.WinDLL("kernel32", use_last_error=True)
    signatures = {
        "CreateJobObjectW": (wt.HANDLE, [ct.c_void_p, wt.LPCWSTR]),
        "CloseHandle": (wt.BOOL, [wt.HANDLE]),
        "SetHandleInformation": (wt.BOOL, [wt.HANDLE, wt.DWORD, wt.DWORD]),
        "SetInformationJobObject": (wt.BOOL, [wt.HANDLE, ct.c_int, ct.c_void_p, wt.DWORD]),
        "AssignProcessToJobObject": (wt.BOOL, [wt.HANDLE, wt.HANDLE]),
        "ResumeThread": (wt.DWORD, [wt.HANDLE]),
        "WaitForSingleObject": (wt.DWORD, [wt.HANDLE, wt.DWORD]),
        "TerminateJobObject": (wt.BOOL, [wt.HANDLE, wt.UINT]),
        "TerminateProcess": (wt.BOOL, [wt.HANDLE, wt.UINT]),
        "GetExitCodeProcess": (wt.BOOL, [wt.HANDLE, ct.POINTER(wt.DWORD)]),
        "QueryInformationJobObject": (wt.BOOL, [wt.HANDLE, ct.c_int, ct.c_void_p, wt.DWORD, ct.c_void_p]),
        "CreateProcessW": (wt.BOOL, [wt.LPCWSTR, wt.LPWSTR, ct.c_void_p, ct.c_void_p,
                                     wt.BOOL, wt.DWORD, ct.c_void_p, wt.LPCWSTR,
                                     ct.POINTER(Startup), ct.POINTER(ProcessInfo)])}
    for name, (result, parameters) in signatures.items():
        getattr(kernel, name).restype = result
        getattr(kernel, name).argtypes = parameters
    return kernel


def check(value):
    if not value:
        raise ct.WinError(ct.get_last_error())


def run_job(command, directory, log, timeout, env, input_path, error_path):
    kernel = kernel_api()
    job = kernel.CreateJobObjectW(None, None)
    check(job)
    limits = ExtendedLimit()
    limits.basic.flags = 0x2000 | 0x200  # KILL_ON_JOB_CLOSE | JOB_MEMORY.
    limits.jobMemory = 1536 * 1024 * 1024
    info = ProcessInfo()
    try:
        check(kernel.SetInformationJobObject(job, 9, ct.byref(limits), ct.sizeof(limits)))
        with Path(log).open("wb") as stream, open(input_path or "NUL", "rb") as inputs, \
                (Path(error_path).open("wb") if error_path else nullcontext(stream)) as errors:
            handle = msvcrt.get_osfhandle(stream.fileno())
            input_handle = msvcrt.get_osfhandle(inputs.fileno())
            error_handle = msvcrt.get_osfhandle(errors.fileno())
            check(kernel.SetHandleInformation(handle, 1, 1))
            check(kernel.SetHandleInformation(input_handle, 1, 1))
            check(kernel.SetHandleInformation(error_handle, 1, 1))
            start = Startup(cb=ct.sizeof(Startup), flags=0x100, stdin=input_handle, stdout=handle, stderr=error_handle)
            environment = ct.create_unicode_buffer("\0".join(f"{key}={value}" for key, value in sorted(env.items())) + "\0\0")
            line = ct.create_unicode_buffer(subprocess.list2cmdline(command))
            # Suspended creation prevents descendants escaping before job assignment.
            check(kernel.CreateProcessW(None, line, None, None, True, 0x08000404,
                                        environment, str(directory), ct.byref(start), ct.byref(info)))
            try:
                check(kernel.AssignProcessToJobObject(job, info.process))
                kernel.ResumeThread(info.thread)
                waited = kernel.WaitForSingleObject(info.process, int(timeout * 1000))
                if waited == 258:
                    kernel.TerminateJobObject(job, 124)
                    kernel.WaitForSingleObject(info.process, 10000)
                code = wt.DWORD()
                check(kernel.GetExitCodeProcess(info.process, ct.byref(code)))
                return accounting(kernel, job, code.value, waited)
            finally:
                kernel.TerminateProcess(info.process, 125)
                kernel.CloseHandle(info.thread)
                kernel.CloseHandle(info.process)
    finally:
        kernel.CloseHandle(job)


def accounting(kernel, job, code, waited):
    cpu = Accounting()
    memory = ExtendedLimit()
    check(kernel.QueryInformationJobObject(job, 1, ct.byref(cpu), ct.sizeof(cpu), None))
    check(kernel.QueryInformationJobObject(job, 9, ct.byref(memory), ct.sizeof(memory), None))
    return {"exitCode": code, "status": "timeout" if waited == 258 else "ok" if code == 0 else "error",
            "cpuSeconds": (cpu.user + cpu.kernel) / 10000000,
            "peakBytes": memory.peakJobMemory}
