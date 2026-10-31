"""OS-released single-writer lock: no overlapping corpus, labels or result writers."""
from contextlib import contextmanager
import os


@contextmanager
def corpus_lock(output):
    path = output / ".writer.lock"
    with path.open("a+b") as stream:
        stream.seek(0, 2)
        if stream.tell() == 0:
            stream.write(b"\0")
            stream.flush()
        stream.seek(0)
        acquire(stream)
        try:
            yield
        finally:
            release(stream)


def acquire(stream):
    try:
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as error:
        raise RuntimeError("Another laboratory command holds this corpus; wait for it to finish") from error


def release(stream):
    stream.seek(0)
    if os.name == "nt":
        import msvcrt
        msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        import fcntl
        fcntl.flock(stream, fcntl.LOCK_UN)
