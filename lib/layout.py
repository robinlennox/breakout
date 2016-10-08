#!/usr/bin/env python
# By Robin Lennox - twitter.com/robberbear

import sys

def banner():
    #Import Colour Scheme
    G,Y,B,R,W = colour()

    print """%s
                 ____                 _               _
                |  _ \               | |             | |
                | |_) |_ __ ___  __ _| | _____  _   _| |_
                |  _ <| '__/ _ \/ _` | |/ / _ \| | | | __|
                | |_) | | |  __/ (_| |   < (_) | |_| | |_
                |____/|_|  \___|\__,_|_|\_\___/ \__,_|\__|%s%s
                # Coded By Robin Lennox - @robberbear
    """%(R,W,Y)

def colour():
    #Check if we are running this on windows platform
    is_windows = sys.platform.startswith('win')

    #Console Colors
    if is_windows:
        G = Y = B = R = W = G = Y = B = R = W = '' #use no terminal colors on windows
    else:
        G = '\033[92m' #green
        Y = '\033[93m' #yellow
        B = '\033[94m' #blue
        R = '\033[91m' #red
        W = '\033[0m'  #white

        return G,Y,B,R,W
