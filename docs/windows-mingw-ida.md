# Windows x64 projects with MinGW-w64 and IDA

Run these commands from a checkout of the Windows MinGW/IDA branch. `uv run decomp` uses the development workspace, normally `~/Decomp-dev`. Set `DECOMP_HOME` to a dedicated folder if you need another workspace and use the same setting for import and launch.

## Set up the tools

1. Install Python 3.12 through uv and run `uv sync --python 3.12`.
2. Install your own licensed copy of IDA with x64 Hex-Rays and IDAPython.
3. Install the appropriate MSYS2 MinGW-w64 C++ compiler. For the GCC 16.1.0 payload with an `msvcrt.dll` import, use the **MINGW64** compiler. The importer checks the GCC version, x64 MinGW target, and CRT before selecting the driver. It checks PATH and the default MSYS2 installation.
4. Run `uv run decomp setup` to prepare decompdecomp's tools. For projects using the Windows Ghidra launcher, put a native Windows JDK 21 or newer on PATH. Verify that `java -version` and `javac -version` both work.

GCC flags start at `-O2` in the generated `tools/configure.py`. Matching source may require the original compilation flags.

## Start a project with IDA

1. Open your own copy of the x64 PE in IDA using the Windows PE loader. Let analysis finish.
2. In IDA, choose **File → Script file** and run [export_hexrays.py](export_hexrays.py). Select a private destination folder in the save dialog. The script writes `ida-functions.json`, `hexrays-drafts.json`, and a copy of the refresh script in that folder.
3. Close the development copy of decompdecomp and import from PowerShell.

   ```powershell
   uv run decomp import-ida 'C:\path\to\module.bin' 'C:\private\ida-export\ida-functions.json' --confirm-own-copy
   uv run decomp
   ```

4. Open the new project marked **(IDA)**. IDA supplies the function list and pseudocode. decompdecomp uses PE unwind information while preparing comparison objects, and objdiff compares GCC output with the original instructions. A byte-identical baseline can use original machine code before any source functions match.

After changing names or types in IDA, run the copy of `export_hexrays.py` inside the project's `.decomp-wtf` folder. New drafts appear in function briefs. Use **Reimport** to refresh function boundaries after committing pending project configuration changes.

## Collaborate

Use the same fork commit and keep the reconstructed source and project configuration in a separate repository. Each collaborator provides an authorized copy of the input and regenerates the IDA exports locally. Keep the original binary under `orig/`, the IDA database and local exports private, and generated builds in `build/`. For a cloned reconstruction, reconfigure using the local compiler path.

```powershell
python tools/configure.py module --gcc 'C:\msys64\mingw64\bin\g++.exe'
ninja prepare
ninja rebuild
```

The IDA importer currently covers one standalone x64 PE. The GCC path recognizes a single MSYS2 version signature in the PE's read-only data.
