# -*- coding: utf-8 -*-

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

def run():
    args = getScriptArgs()
    program = currentProgram
    output_path = args[0] if args else "/tmp/" + program.getName() + "_decompiled.c"

    monitor = ConsoleTaskMonitor()
    decompiler = DecompInterface()
    decompiler.openProgram(program)

    program_name = program.getName()
    print("[Ghidrathon] Decompiling: " + program_name)
    print("[Ghidrathon] Output: " + output_path)

    with open(output_path, "w") as f:
        f.write("// Decompiled by Ghidra (via Ghidrathon)\n")
        f.write("// Program: " + program_name + "\n\n")

        functions = list(program.getFunctionManager().getFunctions(True))
        total = len(functions)
        print("[Ghidrathon] Found " + str(total) + " functions")

        for i, function in enumerate(functions, 1):
            try:
                res = decompiler.decompileFunction(function, 60, monitor)
                if res and res.decompileCompleted():
                    c_code = res.getDecompiledFunction().getC()
                    if c_code:
                        f.write("\n// Function: " + function.getName() + "\n")
                        f.write(str(c_code))
                else:
                    f.write("\n// Function: " + function.getName() + " - failed\n")
            except Exception as e:
                f.write("\n// Function: " + function.getName() + " - error: " + str(e) + "\n")

            if i % 50 == 0:
                print("[Ghidrathon] Progress: " + str(i) + "/" + str(total))

    decompiler.dispose()
    print("[Ghidrathon] Done: " + output_path)

run()
