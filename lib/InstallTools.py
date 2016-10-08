#!/usr/bin/env python
# By Robin Lennox - twitter.com/robberbear

import os
import shutil
from lib.layout import *

#Import Colour Scheme
G,Y,B,R,W = colour()

def gitSetup(makeCommand,checkFile,installName,dirName,remoteURL,verbose,):
    # Check if DIR Exist or not empty
    if not os.path.isdir(dirName):
        os.mkdir(dirName)
        return gitClone(makeCommand,installName,dirName,remoteURL,)
    elif len(os.listdir(dirName)) == 1 or not os.path.isfile(checkFile) :
        shutil.rmtree(dirName)
        return gitClone(makeCommand,installName,dirName,remoteURL,)
    else:
        if verbose:
            print Y+"[*] %s Repo already downloaded" %(installName)+W
        return True

def gitClone(makeCommand,installName,dirName,remoteURL,):
    os.system('git clone %s %s > /dev/null 2>&1' %(remoteURL, dirName))
    os.system('cd %s; %s' %(dirName,makeCommand))
    print G+"[+] Cloned Repo for %s" %(installName)+W
    return True

def checkTools(verbose):
    installName = "ICMP Tunnel"
    dirName = "/opt/icmptunnel"
    checkFile = dirName+'/icmptunnel'
    remoteURL = "https://github.com/jamesbarlow/icmptunnel.git"
    makeCommand = "make > /dev/null 2>&1"
    if not gitSetup(makeCommand,checkFile,installName, dirName,remoteURL,verbose,):
        sys.exit(R+'[!] Missing Tool %s\n' %( installName )+W)

    installName = "DNS Tunnel"
    dirName = "/tmp/iodine"
    checkFile = "/usr/local/sbin/iodine"
    remoteURL = "https://github.com/yarrick/iodine.git"
    makeCommand = "sudo make > /dev/null 2>&1; sudo make install > /dev/null 2>&1"
    if not gitSetup(makeCommand,checkFile,installName, dirName,remoteURL,verbose,):
        sys.exit(R+'[!] Missing Tool %s\n' %( installName )+W)