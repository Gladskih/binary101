"""Real resource contents that invalidate convenient but unsupported filters.

No producer arrays or registration functions are patched: all these bytes go
through the actual rcc compiler and the ordinary Qt runtime oracle.
"""
import hashlib
from xml.sax.saxutils import escape, quoteattr

FAMILIES = ("tiny", "empty-file", "sizes", "metadata-text", "opaque", "small-sets", "compressed-sizes", "payload-decoy")
SIZES = (0, 1, 2, 3, 4, 7, 8, 15, 16, 17, 31, 32, 33, 63, 64, 65,
         127, 128, 129, 255, 256, 257, 4095, 4096, 4097)


def binary_content(seed, size):
    return hashlib.shake_256(seed.encode()).digest(size)


def contents(job, index):
    family = job["family"]
    seed = f"{family}:{job['seed']}:{index}"
    if family in ("tiny", "payload-decoy"):
        return [("tiny.txt", b"x")]
    if family == "empty-file":
        return [("empty.txt", b"")]
    if family in ("sizes", "compressed-sizes"):
        return [(f"size-{size}.bin", binary_content(f"{seed}:{size}", size)) for size in SIZES]
    if family == "metadata-text":
        return [("compiler.txt", b"GCC: this is an application resource, not a compiler identification."),
                ("owner.bin", b"GNU\0"), ("lookalike.bin", b"\0\0\0GCC: a length-prefixed-looking resource")]
    if family == "opaque":
        return [("not-an-image.png", bytes(range(256))), ("no-extension", binary_content(seed, 113))]
    if family == "small-sets":
        return [("first.bin", binary_content(seed + ":first", 3)),
                ("second.bin", binary_content(seed + ":second", 5))]
    raise ValueError(f"Unknown counterexample family: {family}")


def payload_decoy(directory):
    # Plain application data, not passed to qRegisterResourceData. Its bytes can
    # nevertheless satisfy a one-file RCC tree's length-prefixed payload shape.
    text = '#ifdef _WIN32\n#define EXPORT __declspec(dllexport)\n#else\n#define EXPORT __attribute__((visibility("default")))\n#endif\n'
    text += 'static const unsigned char application_fields[] __attribute__((used)) = {0,0,0,1,121};\n'
    text += 'extern "C" EXPORT const unsigned char *lab_application_fields() { return application_fields; }\n'
    (directory / "payload_decoy.cpp").write_text(text, encoding="utf-8")
    return "payload_decoy.cpp"


def assets(directory, job, index):
    salt = hashlib.sha256(f"{job['family']}:{job['seed']}:{index}".encode()).hexdigest()[:12]
    # This ordinary one-byte case reproduces the non-4-aligned GCC data table.
    prefix = "/alignment" if job["family"] == "tiny" else f"/assets/{salt}/{index}"
    entries, expected = [], []
    for number, (alias, content) in enumerate(contents(job, index)):
        name = f"asset{index}-{number}.bin"
        (directory / name).write_bytes(content)
        entries.append(f"<file alias={quoteattr(alias)}>{escape(name)}</file>")
        expected.append({"path": f"{prefix}/{alias}", "sha256": hashlib.sha256(content).hexdigest(), "locale": "C"})
    return prefix, f"<qresource prefix={quoteattr(prefix)}>{''.join(entries)}</qresource>", expected
