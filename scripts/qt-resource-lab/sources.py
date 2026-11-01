"""Deterministic assets, actual rcc output, and compiled negative controls."""
import hashlib
from pathlib import Path
import re
import shutil
import struct
from process import run
from truth import arrays_from_cpp
from counterexample_assets import FAMILIES as COUNTEREXAMPLES, assets as counterexample_assets, payload_decoy

TEMPLATES = Path(__file__).parent


def assets(directory, job, index):
    if job["family"] in COUNTEREXAMPLES:
        return counterexample_assets(directory, job, index)
    salt = hashlib.sha256(f"{job['family']}:{job['seed']}:{index}".encode()).hexdigest()[:12]
    prefix = f"/assets/{salt}/{index}"
    text = (f"Qt resource {salt}: independent oracle.\n" * 80).encode()
    (directory / f"message{index}.txt").write_bytes(text)
    (directory / f"icon{index}.svg").write_text(
        f'<svg xmlns="http://www.w3.org/2000/svg"><text>{salt}</text></svg>', encoding="utf-8")
    alias = "данные-λ.txt" if job["family"] == "localized" else "message.txt"
    xml = f'<qresource prefix="{prefix}"><file alias="{alias}">message{index}.txt</file><file alias="icon.svg">icon{index}.svg</file></qresource>'
    expected = [{"path": f"{prefix}/{alias}", "sha256": hashlib.sha256(text).hexdigest()},
                {"path": f"{prefix}/icon.svg", "sha256": hashlib.sha256((directory / f"icon{index}.svg").read_bytes()).hexdigest()}]
    if job["family"] == "shared":
        xml += f'<qresource prefix="{prefix}"><file alias="copy.txt">message{index}.txt</file></qresource>'
        expected.append({"path": f"{prefix}/copy.txt", "sha256": hashlib.sha256(text).hexdigest()})
    if job["family"] == "localized":
        translated = f"Übersetzung {salt}".encode()
        (directory / "de.txt").write_bytes(translated)
        xml += f'<qresource prefix="{prefix}" lang="de_DE"><file alias="{alias}">de.txt</file></qresource>'
        expected.append({"path": f"{prefix}/{alias}", "sha256": hashlib.sha256(translated).hexdigest(), "locale": "de_DE"})
    for entry in expected:
        entry.setdefault("locale", "C")
    return prefix, xml, expected


def prepare(directory, sdk, job):
    directory.mkdir(parents=True, exist_ok=True)
    for name in ("oracle.cpp", "entry.cpp", "loader.cpp"):
        shutil.copyfile(TEMPLATES / name, directory / name)
    resources, commands = [], []
    if job["family"] not in ("empty", "plain", "magic"):
        for index in range(2 if job["family"] in ("multiple", "mixed", "small-sets") else 1):
            resources.append(generate_resource(directory, sdk, job, index, commands))
    source_files = [record["cpp"] for record in resources]
    controls = [payload_decoy(directory)] if job["family"] == "payload-decoy" else []
    source_files += controls
    negative = job["family"] in ("magic", "bad-hash", "bad-link", "bad-size", "mixed")
    if negative:
        source_files = negative_source(directory, job, resources)
    if job["family"] == "unused":
        retain_unregistered(directory, resources)
    if job["family"] == "plain":
        (directory / "oracle.cpp").write_text(
            '#ifdef _WIN32\n#define EXPORT __declspec(dllexport)\n#else\n#define EXPORT __attribute__((visibility("default")))\n#endif\n'
            'extern "C" EXPORT const char *lab_probe() { return "{\\"files\\":[]}"; }\n'
            'extern "C" EXPORT const char *lab_validate_file(const char *) { return "{\\"error\\":\\"no Qt\\"}"; }\n', encoding="utf-8")
    return {"resources": resources, "sourceFiles": source_files, "negative": negative,
            "commands": commands, "registration": registration_for(job["family"]),
            "retainedControlSources": controls}


def retain_unregistered(directory, resources):
    for record in resources:
        disable_registration(directory / record["cpp"])


def registration_for(family):
    absent = ("empty", "plain", "unused", "magic", "bad-hash", "bad-link", "bad-size", "mixed")
    return "absent" if family in absent else "generated"


def generate_resource(directory, sdk, job, index, commands):
    prefix, xml, expected = assets(directory, job, index)
    qrc = f"resource{index}.qrc"
    cpp = f"qrc_resource{index}.cpp"
    (directory / qrc).write_text(f"<RCC>{xml}</RCC>", encoding="utf-8")
    algorithm = "zstd" if job["family"] == "zstd" else "zlib" if job["family"] in ("compressed", "compressed-sizes") else "none"
    flags = ["--format-version", str(job["rccVersion"]), "--compress-algo", algorithm]
    if algorithm != "none":
        flags += ["--threshold", "0"]
    for extra, output in (([], cpp), (["--binary"], f"resource{index}.rcc")):
        commands.append(run([sdk["rcc"], *flags, *extra, "-name", f"resource{index}", qrc, "-o", output],
                            directory, directory / f"rcc-{index}-{len(extra)}.log", environment=sdk["environment"]))
    return {"prefix": prefix, "expected": expected, "cpp": cpp, "qres": f"resource{index}.rcc"}


def disable_registration(path):
    text = path.read_text(encoding="utf-8")
    text, count = re.subn(r"initializer\(\)\s*\{[^{}]*qInitResources[^{}]*\}", "initializer() {}", text)
    text = re.sub(r"~initializer\(\)\s*\{[^{}]*\}", "~initializer() {}", text)
    if count != 1:
        raise ValueError("Unrecognized rcc initializer; refusing unregistered label")
    # Public retained pointer exports keep all arrays through LTO without registering them.
    text += '\n#ifdef _WIN32\n#define LAB_KEEP __declspec(dllexport)\n#else\n#define LAB_KEEP __attribute__((used,visibility("default")))\n#endif\n'
    for name in ("struct", "name", "data"):
        text += f'extern "C" LAB_KEEP const unsigned char *lab_unused_{name}() {{ return qt_resource_{name}; }}\n'
    path.write_text(text, encoding="utf-8")


def negative_source(directory, job, resources):
    data = bytearray(b"qres GVariant raVGtnai qt_resource_struct qt_resource_name qt_resource_data\0")
    for resource in resources:
        blob = bytearray((directory / resource["qres"]).read_bytes())
        tree, _, names = struct.unpack_from(">III", blob, 8)
        if job["family"] == "bad-link":
            struct.pack_into(">I", blob, tree + 10, 0xffffffff)
        elif job["family"] == "bad-size":
            # A broken qres header alone leaves valid unregistered arrays behind.
            # Corrupt the retained payload region too, before changing its offset.
            data_start = struct.unpack_from(">I", blob, 12)[0]
            data_end = min(value for value in (tree, names, len(blob)) if value > data_start)
            blob[data_start:data_end] = b"\xff" * (data_end - data_start)
            struct.pack_into(">I", blob, 12, len(blob) + 4096)
        else:
            # Corrupt every stored Qt name hash, not only one optional branch.
            cursor = names
            while cursor < tree:
                length = struct.unpack_from(">H", blob, cursor)[0]
                struct.pack_into(">I", blob, cursor + 2, 0xffffffff)
                cursor += 6 + length * 2
        data += blob
    text = 'static const volatile unsigned char decoy[] __attribute__((used,section(".gresource.decoy"))) = {' + ",".join(map(str, data)) + '};\n'
    text += 'extern "C" unsigned lab_decoy() { unsigned value=0; for (auto byte:decoy) value+=byte; return value; }\n'
    tables = [negative_tables(directory, job, resource, index) for index, resource in enumerate(resources)]
    declarations = "".join(f'extern "C" unsigned lab_tables{index}();\n' for index in range(len(tables)))
    calls = "".join(f'value += lab_tables{index}();' for index in range(len(tables)))
    text = declarations + text.replace("return value;", calls + "return value;")
    (directory / "decoy.cpp").write_text(text, encoding="utf-8")
    return ["decoy.cpp", *tables]


def negative_tables(directory, job, resource, index):
    arrays = {key: bytearray(value) for key, value in arrays_from_cpp(directory / resource["cpp"]).items()}
    if job["family"] == "bad-link":
        struct.pack_into(">I", arrays["struct"], 10, 0xffffffff)
    elif job["family"] == "bad-size":
        arrays["data"][:] = b"\xff" * len(arrays["data"])
    else:
        cursor = 0
        while cursor < len(arrays["name"]):
            length = struct.unpack_from(">H", arrays["name"], cursor)[0]
            struct.pack_into(">I", arrays["name"], cursor + 2, 0xffffffff)
            cursor += 6 + length * 2
    declarations = []
    loops = []
    for name, content in arrays.items():
        declarations.append(f'static const volatile unsigned char qt_resource_{name}[] = {{' + ",".join(map(str, content)) + '};\n')
        loops.append(f'for (auto byte: qt_resource_{name}) value += byte;')
    text = "".join(declarations) + f'extern "C" unsigned lab_tables{index}() {{ unsigned value=0;' + "".join(loops) + 'return value; }\n'
    name = f"decoy_tables{index}.cpp"
    (directory / name).write_text(text, encoding="utf-8")
    return name
