import os
import subprocess

GHIDRA_INSTALL_DIR  = "/Applications/ghidra_12.0.4_PUBLIC"
GHIDRA_HEADLESS     = os.path.join(GHIDRA_INSTALL_DIR, "support", "analyzeHeadless")
GHIDRA_PROJECT_PATH = "/Users/davidnguyen/PycharmProjects/TheKnights/Cyberbot/CyberbotGhidraProject"
GHIDRA_PROJECT_NAME = "Decompiler"
GHIDRA_SCRIPTS_PATH = "/Users/davidnguyen/PycharmProjects/TheKnights/Cyberbot/PythonScripts/GhidraDecompileScript"
JEP_LIB_PATH        = "/Users/davidnguyen/PycharmProjects/TheKnights/bin/lib/python3.14/site-packages/jep"

def ghidraDecompile(filepath, mountPoint, filename):
    output_file = os.path.join(mountPoint, f"{os.path.splitext(filename)[0]}_decompiled.c")

    env = os.environ.copy()
    env["DYLD_LIBRARY_PATH"] = JEP_LIB_PATH

    cmd = [
        GHIDRA_HEADLESS,
        GHIDRA_PROJECT_PATH,
        GHIDRA_PROJECT_NAME,
        "-import", filepath,
        "-scriptPath", GHIDRA_SCRIPTS_PATH,
        "-postScript", "GhidraDecompile.py", output_file,
        "-deleteProject",
    ]

    print(f"Running Ghidra headless on: {filepath}")

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=600,
            env=env
        )

        print("=== FULL GHIDRA OUTPUT ===")
        print(result.stdout)
        print("=== END OUTPUT ===")
        print(f"Return code: {result.returncode}")

        if os.path.exists(output_file):
            print(f"Decompilation complete: {output_file}")
            # os.remove(filepath)
            return output_file
        else:
            print("[ERROR] Output file not created")
            return None

    except subprocess.TimeoutExpired:
        print("[ERROR] Ghidra timed out")
        return None
    except Exception as e:
        print(f"[ERROR] {e}")
        return None

ghidraDecompile("/Users/davidnguyen/PycharmProjects/TheKnights/TestItems/ExecutableFiles/YoureCookedIfOpen.exe", "/Users/davidnguyen/PycharmProjects/TheKnights/Cyberbot/Decompiled", "Connect5")