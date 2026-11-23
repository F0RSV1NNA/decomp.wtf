"""Export function boundaries and pseudocode from the current x64 PE database."""

import hashlib
import json
import shutil
import struct
from pathlib import Path
from tempfile import NamedTemporaryFile

import ida_auto
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_lines
import ida_nalt
import idautils
import idc


def write_export(folder, name, data):
    with NamedTemporaryFile(mode="w", encoding="utf-8", dir=folder, delete=False) as stream:
        temp = Path(stream.name)
        json.dump(data, stream, ensure_ascii=False)
    try:
        temp.replace(folder / name)
    finally:
        temp.unlink(missing_ok=True)


def main():
    script = Path(__file__).resolve()
    if len(idc.ARGV) > 1:
        folder = Path(idc.ARGV[1]).resolve()
    elif script.parent.name == ".decomp-wtf":
        folder = script.parent
    else:
        destination = ida_kernwin.ask_file(True, "*.json", "Save IDA function export as ida-functions.json")
        if not destination:
            return
        folder = Path(destination).resolve().parent

    original = Path(ida_nalt.get_input_file_path()).read_bytes()
    if ida_nalt.retrieve_input_file_sha256() != hashlib.sha256(original).digest():
        raise RuntimeError("The original file no longer matches this IDA database")
    pe = struct.unpack_from("<I", original, 0x3C)[0]
    if (original[pe:pe + 6] != b"PE\0\0\x64\x86"
            or struct.unpack_from("<H", original, pe + 24)[0] != 0x20B):
        raise RuntimeError("Open a Windows x64 PE in IDA before exporting")
    image_base = struct.unpack_from("<Q", original, pe + 48)[0]
    sha1 = hashlib.sha1(original).hexdigest()
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        raise RuntimeError("The x64 Hex-Rays decompiler is unavailable")

    delta = image_base - ida_nalt.get_imagebase()
    rows, drafts = [], {}
    for ea in idautils.Functions():
        function = ida_funcs.get_func(ea)
        if function is None:
            continue
        address = ea + delta
        rows.append({"entry": address, "end": function.end_ea + delta, "name": ida_funcs.get_func_name(ea),
                     "source": "DEFAULT", "thunk": bool(function.flags & ida_funcs.FUNC_THUNK)})
        try:
            code = ida_hexrays.decompile(ea)
        except ida_hexrays.DecompilationFailure:
            continue
        if code is not None:
            drafts[str(address)] = "\n".join(ida_lines.tag_remove(line.line) for line in code.get_pseudocode())
    if not rows or not drafts:
        raise RuntimeError("IDA produced no usable analysis")

    folder.mkdir(parents=True, exist_ok=True)
    write_export(folder, "hexrays-drafts.json", {"sha1": sha1, "drafts": drafts})
    write_export(folder, "ida-functions.json", {"sha1": sha1, "functions": rows})
    helper = folder / "export_hexrays.py"
    if script != helper:
        shutil.copyfile(script, helper)
    print(f"Exported {len(drafts)} Hex-Rays drafts and {len(rows)} IDA function entries to {folder}")


if __name__ == "__main__":
    main()
