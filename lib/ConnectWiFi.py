#!/usr/bin/env python
# By Robin Lennox - twitter.com/robberbear

import os
import time
import subprocess
import wifi
import netifaces
from wifi import Cell, Scheme

from Layout import *

#Import Colour Scheme
G,Y,B,R,W = colour()

def attemptWiFiConnect(ssidName,wirelessInterface):
    try:
        #Need if network-manager is installed
        os.system('sudo service network-manager stop > /dev/null 2>&1')
        os.system('sudo rfkill unblock wifi; sudo rfkill unblock all')
        os.system('sudo ifconfig %s up' %(wirelessInterface,))
        # Allow the interface to come backup
        time.sleep(5)
        os.system('sudo iwconfig %s essid "%s"' %(wirelessInterface,ssidName,))

        # Timeout if DHCP doesn't work
        answer = subprocess.check_output('sudo timeout 15s sh -c \'sudo dhclient %s\'' %(wirelessInterface,), shell=True, stderr=subprocess.STDOUT)
        return True
    except:
        return False

def openWIFI(isPi):
    if isPi:
        subprocess.check_output("sudo sh -c 'echo 0 >/sys/class/leds/led0/brightness'", shell=True)
    PWD=os.path.dirname(os.path.realpath(__file__))
    interfaces = getInterfaces()
    for wirelessInterface in interfaces:
        os.system('sudo rfkill unblock wifi; sudo rfkill unblock all')
        print B+"[-] Trying interface %s" %(wirelessInterface,)+W
        os.system('sudo ifconfig %s up' %(wirelessInterface,))
        # Will fail if already connected
        cells = wifi.Cell.all(wirelessInterface)

        #result_list = set([cell.ssid for cell in cells])
        #print result_list

        wifilist = createWifiBlacklist()
        wifiConnected = False
        for cell in cells:
            if cell.ssid not in wifilist:
                if not cell.encrypted and str(cell.ssid):
                    wifilist.append(cell.ssid)
                    print Y+"[*] Attempting to connect to SSID %s on %s" %(cell.ssid,wirelessInterface,)+W
                    wifiConnected = attemptWiFiConnect(cell.ssid,wirelessInterface)
                    if wifiConnected:
                        print G+"[+] Successfully connected to SSID %s on %s" %(cell.ssid,wirelessInterface,)+W
                        writeFile('/opt/breakout/logs/wifi.txt',time.strftime("%b %-d %H:%M:%S"),cell.ssid,"Yes","Yes")
                        if isPi:
                            subprocess.check_output("sudo sh -c 'echo 1 >/sys/class/leds/led0/brightness'", shell=True)
                        break
                    else:
                        print R+"[x] Failed to connect to SSID %s on %s" %(cell.ssid,wirelessInterface,)+W
                        writeFile('/opt/breakout/logs/wifi.txt',time.strftime("%b %-d %H:%M:%S"),cell.ssid,"Yes","No")
                elif cell.ssid:
                    print R+"[x] Passing encrypted SSID %s on %s" %(cell.ssid,wirelessInterface,)+W
                    wifilist.append(cell.ssid)
                    writeFile('/opt/breakout/logs/wifi.txt',time.strftime("%b %-d %H:%M:%S"),cell.ssid,"No","No")
                    
def getInterfaces():
    interface_list = netifaces.interfaces()
    # Get Wireless Interfaces
    return filter(lambda x: 'wl' in x,interface_list)

def writeFile(fileName,timeStamp,ssid,openStatus,connected):
    with open(fileName, 'a') as file:
        file.write("%s %s Open=%s Connected=%s \n" % (timeStamp,ssid,openStatus,connected))

def createWifiBlacklist():
    wifiBlacklist = []
    timeout='30 min'

    # Audit's Wifi in the area
    answers = subprocess.check_output('awk -v d1="$(date --date="-'+timeout+'" "+%b %_d %H:%M")" -v d2="$(date "+%b %_d %H:%M")" \'$0 > d1 && $0 < d2 || $0 ~ d2\' /opt/breakout/logs/wifi.txt | awk \'NF{NF-=2};1\' | cut -d\' \' -f4- | sort | uniq -c', shell=True, stderr=subprocess.STDOUT).rstrip().split('\n')
    # Will attempt to stay connected to Wifi
    #answers = subprocess.check_output('awk -v d1="$(date --date="-'+timeout+'" "+%b %_d %H:%M")" -v d2="$(date "+%b %_d %H:%M")" \'$0 > d1 && $0 < d2 || $0 ~ d2\' /opt/breakout/logs/wifi.txt | grep -v "Yes\|No Yes" |awk \'NF{NF-=2};1\' | cut -d\' \' -f4- | sort | uniq -c', shell=True, stderr=subprocess.STDOUT).rstrip().split('\n')
    try:
        for answer in answers:
            scanNum = answer.lstrip().split(' ')[0]
            ssidName = ' '.join(map(str,answer.lstrip().split(' ')[1:]))
            if not answer or int(scanNum) > 5:
                print W+"[!] Skipping SSID %s already scanned %s times in %s." %(ssidName,scanNum,timeout,)+W
                wifiBlacklist.append(ssidName)
    except:
        pass

    return wifiBlacklist

def main():
    isPi = os.path.isfile('/sys/class/leds/led1/trigger')
    try:
        currentSSID = subprocess.check_output("iwgetid -r", shell=True)

        if not currentSSID in "\n":
            if isPi:
                subprocess.check_output("sudo sh -c 'echo 1 >/sys/class/leds/led0/brightness'", shell=True)
            print G+"[+] Already connected to SSID: %s" %(currentSSID.replace('\n', ''))+W
        else:
            openWIFI(isPi)
    except:
        openWIFI(isPi)

if __name__ == '__main__':
    main ()
