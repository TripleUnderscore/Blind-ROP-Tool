
from print_tools import printInfo, ccya, cthin, cver, cend

# A déplacer
def exploitInfo():
    print(cver + "\nInformations about --exploit option :" + cend)
    print(cver + "\t0 :" + cend + cthin + " print this help and exit." + cend)
    print(cver + "\t1 :" + cend + cthin + " perform a simple leak of the values of the targeted binary' stack ; does not launch any other attack." + cend)
    print(cver + "\t2 :" + cend + cthin + " launch the attack from A to Z.\n" + cend)
    exit(0)

# A déplacer
def infoArch():
    print(cver + "\nInformations about --architecture option :" + cend)
    print(cver + "\tdefault :" + cthin + " the tool will try to guess the targeted architecture." + cend)
    print(cver + "\t0 :" + cthin + " print this help and exit." + cend)
    print(cver + "\t1 :" + cthin + " the binary is a x86 binary launched in a 32 bits environment." + cend)
    print(cver + "\t2 :" + cthin + " the binary is a x86 binary launched in a 64 bits environment." + cend)
    print(cver + "\t3 :" + cthin + " the binary is a x86_64 binary launched in a 64 bits environment." + cend)
    print(cver + "\t4 :" + cthin + " the binary is an ARM binary launched in a 32 bits environment.\n" + cend)
    exit(0)

def printFileValuesExample():
    printInfo("The adresses and offsets file has to be like this for an x64 ELF binary :")
    print(ccya + '''{
    "leaked_at_start": {
        "canary": "0x6d2387a6de56d800", "rbp": "0x0", "ret_adr": "0x0"
    },
    "binary_adr": {
        "stop_gadget": "0x0", "brop_gadget": "0x0", "leak_adr": "0x0", "binary_base": "0x0"
    },
    "libc_adr": {
        "libc_base": "0x0", "dup2": "0x0", "system": "0x0", "binsh_str": "0x0"
    },
    "offset": {
        "libc_offset": "-0x0", "stop_offset": "0x0", "brop_offset": "0x0"
    }
}''' + cend)
    exit(0)
