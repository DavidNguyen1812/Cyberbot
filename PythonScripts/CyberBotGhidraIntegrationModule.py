from __future__ import annotations

from CyberBotRuntimeModule import *

def ghidraDecompile(filepath: str, mountPoint: str, filename: str) -> str:
    """
    Description: Using Ghidra analyzeHeadless and Ghidrathon to de-assemble an executatble/binary program
    :param filepath: The filepath to the binary
    :param mountPoint: The path to write the decompiled/source code of the binary
    :param filename: The filename of the binary
    :return: The path of the decompiled/source code of the binary or ERROR
    """
    outputFile = os.path.join(mountPoint, f"{os.path.splitext(filename)[0]}_{uuid.uuid4().hex[:10]}_decompiled.txt")

    env = os.environ.copy()
    if JEPLIB_PATH is not None:
        env["DYLD_LIBRARY_PATH"] = JEPLIB_PATH

    cmd = [
        GHIDRA_HEADLESS_EXECUTABLE,  # Calling the Ghidra analyzeHeadless program
        GHIDRA_TEMP_PROJECTS,  # Ghidra project folder to create a temp project
        f"{uuid.uuid4().hex}CyberbotDecompile",  # Ghidra project name
        "-import", filepath,  # Importing the binary file to be decompiled
        "-scriptPath", GHIDRA_DECOMPILE_SCRIPT, # The directory that contain the Python script contains the decompilation instructions to be executed by Ghidrathon
        "-postScript", "CyberBotGhidraDecompileModule.py", outputFile, # The name of the Python script contains the decompilation instructions
        "-deleteProject",  # Delete the temp project after decompilation
    ]

    print(f"Running Ghidra headless on: {filepath}")

    try:
        subprocess.run(cmd, timeout=600, env=env, check=True)
        print(f"Decompilation and export complete. Cleaning up compiled file {filename}")
        os.remove(filepath)
        return outputFile
    except subprocess.TimeoutExpired:
        print("[Ghidra ERROR] Ghidra timed out")
        os.remove(filepath)
        return "ERROR"
    except Exception as e:
        print(f"[Ghidra ERROR] {e}")
        os.remove(filepath)
        return "ERROR"
