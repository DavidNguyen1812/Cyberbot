import r2pipe
import os

# Function to get decompiled code
def radare2Decompilation(filePath):
    try:
        decompiledCode = ''
        # Open the binary in radare2
        r2 = r2pipe.open(filePath)
        
        # Analyze the binary to find functions and other info
        print("[*] Analyzing binary...")
        r2.cmd("aaa")
        for function in r2.cmd("afl").split("\n")[0:]:
            # Seek to the desired function
            r2.cmd(f"s {function[:11]}")
    
            # Decompile the function using the r2ghidra plugin
            print(f"[*] Decompiling function: {function[:11]}")
            decompiledCode += r2.cmd("pdg")
        
        # Close the r2pipe instance
        r2.quit()
        with open(f"/home/TheKnights/Downloads/{os.path.basename(filePath).split('.')[0]}.txt", "w") as outputFile:
            outputFile.write(decompiledCode)
        
    except Exception as e:
        return f"An error occurred: {e}"

print(radare2Decompilation("/home/TheKnights/Downloads/Connect5"))
