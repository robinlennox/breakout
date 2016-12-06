#!/usr/bin/env python
# By Robin Lennox - twitter.com/robberbear
import subprocess

from Layout import *

#Import Colour Scheme
G,Y,B,R,W = colour()

def checkRunningState(processName):
    numberOfProcesses = int(subprocess.check_output('ps -eo command | grep "^python" | grep %s | wc -l' %(processName), shell=True, stderr=subprocess.STDOUT))
    if numberOfProcesses > 1:
        print R+"[x] %s already running" %(processName)+W
        sys.exit(0)
