

from pwn import u64

"""
Some colours can change from an OS to another one...
So don't break balls about that plz
"""

cthin = '\x1b[1;32;0m'  # Can't remember...but nothing on Windows

clig = '\x1b[1;29;1m'   # Light whote
cbro = '\x1b[1;30;1m'   # Dark Grey / Brown
cred = '\x1b[1;31;1m'   # Red
cver = '\x1b[1;32;1m'   # Green
cjau = '\x1b[1;33;1m'   # Yellow
cble = '\x1b[1;34;1m'   # Blue
cpur = '\x1b[1;35;1m'   # Purple
ccya = '\x1b[1;36;1m'   # Cyan
cend = '\x1b[0m'


 # peut-être virer les exit() des fonctions de printage

def printDone(string):
    print(cble + "[+] " + string + cend)
    exit(0)

def printError(string):
    print(cred + "[X] " + string + cend)

def printDiscretInfo(string):
    print(cbro + "[i] " + string + cend)

def printInfo(string):
    print(clig + "[i] " + string + cend)

def printData(string):
    print(ccya + "[>] " + string + cend)

def printStrongWarning(string):
    print(cpur + "[x] " + string + cend)

def printWarning(string):
    print(cjau + "[!] " + string + cend)

def printQuestion(string):
    print(cver + "[?] " + string + cend)


def crPrint(string, adr, ne):

    if ne == 1:
        print(cver + "[+] " + string + " :  {}".format(hex(u64(adr))) + cend, end='')
    else:
        print(cver + "[+] " + string + " :  {}".format(hex(u64(adr))) + cend)
    return

# function PrintTitle ([string] $title)
# {
    # Write-Host "`n    " $title -fore Gray
# }
