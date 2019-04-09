#!/usr/bin/env python
# By Robin Lennox - twitter.com/robberbear
import subprocess
import sys

from lib.Layout import colour

# Import Colour Scheme
G, Y, B, R, W = colour()


def checkRunningState(processName):
    numberOfProcesses = int(subprocess.check_output(
        'ps | grep "^python" | grep %s | wc -l' % (processName), shell=True, stderr=subprocess.STDOUT))
    if numberOfProcesses > 1:
        print(R+"[x] {0} already running".format(processName)+W)
        sys.exit(0)
