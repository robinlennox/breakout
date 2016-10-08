#!/usr/bin/env python
# By Robin Lennox - twitter.com/robberbear

import urllib2

def internetStatus():
    try:
        response=urllib2.urlopen('http://google.com',timeout=1)
        return True
    except urllib2.URLError as err: pass
    return False