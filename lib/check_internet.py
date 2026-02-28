#!/usr/bin/env python
# By Robin Lennox - twitter.com/robberbear

import requests


def internetStatus():
    try:

        requests.get('https://www.google.com', timeout=1)
        return True
    except:
        return False
