#!/usr/bin/python3

import argparse
from pwn import *
from sys import exit

from brop import checkBuildID

CTHIN = '\x1b[1;32;0m'

CLIG = '\x1b[1;29;1m'   # Blanc éclatant
CBRO = '\x1b[1;30;1m'   # Gris foncé / Brun
CRED = '\x1b[1;31;1m'   # Rouge
CVER = '\x1b[1;32;1m'   # Vert
CJAU = '\x1b[1;33;1m'   # Jaune
CBLE = '\x1b[1;34;1m'   # Bleu
CPUR = '\x1b[1;35;1m'   # Violet
CCYA = '\x1b[1;36;1m'   # Cyan
CEND = '\x1b[0m'

def printDone(STR):
    print(CVER + "[+] " + STR + CEND)
    exit(0)
def printError(STR):
    print(CRED + "[X] " + STR + CEND)
    exit(1)
def printInfo(STR):
    print(CPUR + "[I] " + STR + CEND)
def printLight(STR):
    print(CCYA + "[O] " + STR + CEND)
def printWarning(STR):
    print(CJAU + "[!] " + STR + CEND)


def persoInfo():
    print(CVER + "\nInformations about --exploit option :" + CEND)
    print(CVER + "\t0 :" + CEND + CTHIN + " print this help and exit." + CEND)
    print(CVER + "\t1 :" + CEND + CTHIN + " perform a simple leak of the values of the targeted binary' stack." + CEND)
    print(CVER + "\t2 :" + CEND + CTHIN + " launch the attack from A to Z.\n" + CEND)
    exit(0)


def persoInfoArch():
    print(CVER + "\nInformations about --architecture option :" + CEND)
    print(CVER + "\tdefault :" + CTHIN + " the tool will try to guess the targeted architecture." + CEND)
    print(CVER + "\t0 :" + CTHIN + " print this help and exit." + CEND)
    print(CVER + "\t1 :" + CTHIN + " the binary is a x86 binary launched in a 32 bits environment." + CEND)
    print(CVER + "\t2 :" + CTHIN + " the binary is a x86 binary launched in a 64 bits environment." + CEND)
    print(CVER + "\t3 :" + CTHIN + " the binary is a x86_64 binary launched in a 64 bits environment." + CEND)
    print(CVER + "\t4 :" + CTHIN + " the binary is an ARM binary launched in a 32 bits environment.\n" + CEND)
    exit(0)


def checkParameter(ExploitStructure):

    parser          = argparse.ArgumentParser()
    conflict        = parser.add_mutually_exclusive_group()

    parser.add_argument("target",               help="give target parameters; use following syntax: HOST:PORT", type=str)

    parser.add_argument("-a", "--architecture", help="indicate architecture and env ; use 0 to get more information", choices = [0, 1, 2, 3, 4], type=int)

    parser.add_argument("-d", "--debug",        help="show debugging informations during execution", action="store_true")
    parser.add_argument("-e", "--exploit",      help="launching standard exploitation ; use 0 to get more information", choices = [0, 1, 2], default = 2, type=int)
    parser.add_argument("-s", "--silent",       help="make pwntools silent", action="store_true")
    parser.add_argument("-hv", "--handvalues",  help="use values set manually in the script", action="store_true")
    parser.add_argument("-p", "--pause",        help="set a value for the sleep() function; default is 0.03s", type=int)

    conflict.add_argument("-b", "--buildid",    help="pass buildid for specific libc", type=str)
    conflict.add_argument("-n", "--nolibcleak", help="don't perform libc leak ; be sure you already have a libc fragment from which read a BuildID", action="store_true")
    # concernant cette derniere option, indiquer le chemin du cache que Python utilise pour stocker les libc telechargees
    args = parser.parse_args()

    if args.silent:
        context.log_level='error'
    if args.debug:
        context.log_level='debug'

    IDs = args.target
    try:
        ExploitStructure.HOST = IDs.split(':')[0]
        ExploitStructure.PORT = int(IDs.split(':')[1], 10)
    except (IndexError, ValueError):
        printError("Wrong host/port")

    if args.exploit == 0:
        persoInfo()
    else:
        ExploitStructure.EXPLOIT = args.exploit

    if args.architecture == 0:
        persoInfoArch()
    else:
        ExploitStructure.ARCH = args.architecture
        if ExploitStructure.ARCH == 4:
            printInfo("ARM architecture option is not implemented yet")
            exit(2)
    
    ExploitStructure.HAND = args.handvalues
    if args.pause:
        ExploitStructure.DODO = args.pause

    ExploitStructure.NOLIBLEAK   = args.nolibcleak
    if args.buildid:
        ExploitStructure.BUILDID = args.buildid
        BUILDIDOK = checkBuildID(ExploitStructure.BUILDID)
        if (BUILDIDOK != 1):
            printError("BuildID error, can't exploit the binary")
            exit(1)

        ExploitStructure.NOLIBLEAK   = True


#mettre une infor conernant le non leak si buildid, ainsi qu'empêcher les deux options
