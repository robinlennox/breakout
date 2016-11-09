#!/usr/bin/env python
# By Robin Lennox - twitter.com/robberbear

import os
import shutil
from lib.Layout import *
from lib.CheckInternet import *

#Import Colour Scheme
G,Y,B,R,W = colour()

def gitSetup(makeCommand,checkFile,installName,dirName,remoteURL,verbose,):
    # Check if DIR Exist or not empty
    if not os.path.isfile(checkFile):
        try:
            shutil.rmtree(dirName)
        except:
            pass
        os.mkdir(dirName)
        return gitClone(makeCommand,installName,dirName,remoteURL,)
    else:
        if verbose:
            print Y+"[*] %s Repo already downloaded" %(installName)+W
        return True

def gitClone(makeCommand,installName,dirName,remoteURL,):
    try:
        if internetStatus():
            os.system('git clone %s %s > /dev/null 2>&1' %(remoteURL, dirName))
            if os.path.isdir(dirName):
                os.system('cd %s; %s' %(dirName,makeCommand))
                print G+"[+] Cloned Repo for %s" %(installName)+W
                return True
    except:
        pass

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
        sys.exit(R+'[!] Missing Tool %s and unable to download\n' %( installName )+W)

def checkFolders(PWD,):
    logsLOC=PWD+'/logs'
    if not os.path.exists(logsLOC):
        print G+"[+] Missing folder logs created"+W
        os.makedirs(logsLOC)

def checkWiFiCron(PWD,):
    # Auto connect to wifi
    checkWIFILOC = PWD+'/lib/ConnectWiFi.py'
    if checkWIFILOC not in open('/etc/crontab').read():
        with open('/etc/crontab', "a") as file:
            print G+"[+] Added connect to WiFi try every minute in /etc/crontab"+W
            file.write("*/1 * * * * root python %s > /dev/null 2>&1\n" %(checkWIFILOC))