#!/usr/bin/env python
# By Robin Lennox - twitter.com/robberbear

import netifaces
import subprocess
import os
import time

import wifi

from lib.ScriptManagement import checkRunningState
from lib.Layout import colour

# Import Colour Scheme
G, Y, B, R, W = colour()


def attemptWiFiConnect(ssidName, wirelessInterface):
    count = 1
    stopCount = 5
    status = False
    subprocess.check_output("rfkill unblock wifi; rfkill unblock all; pkill udhcpc", shell=True,
                            stderr=subprocess.STDOUT).decode('utf-8')
    subprocess.check_output("ifconfig {0} down".format(wirelessInterface, ), shell=True,
                            stderr=subprocess.STDOUT).decode('utf-8')
    subprocess.check_output("iwconfig {0} essid any".format(wirelessInterface, ), shell=True,
                            stderr=subprocess.STDOUT).decode('utf-8')
    subprocess.check_output("ifconfig {0} up".format(wirelessInterface, ), shell=True, stderr=subprocess.STDOUT).decode(
        'utf-8')
    subprocess.check_output("iwconfig {0} essid \"{1}\"".format(wirelessInterface, ssidName, ), shell=True,
                            stderr=subprocess.STDOUT).decode('utf-8')
    # Allow the interface to come backup
    waitTime = 5
    time.sleep(waitTime)
    print(
        B + "[-] Waiting for DHCP Address from interface {0}".format(wirelessInterface) + W)
    while (count < stopCount):
        try:
            subprocess.check_output("udhcpc -i {0} -t {1} -n".format(wirelessInterface, count), shell=True,
                                    stderr=subprocess.STDOUT).decode('utf-8')
            status = True
            break
        except Exception:
            count = count + 1
            if count == stopCount:
                print(
                    Y + "[*] Failed to get DHCP address for SSID {0} on {1}".format(ssidName, wirelessInterface, ) + W)
                print(
                    W + "[!] Trying disabling network management of host such as 'sudo service network-manager stop'\n" + W)

    return status


def openWIFI(isPi):
    if isPi:
        subprocess.check_output(
            "sh -c 'echo 0 >/sys/class/leds/led0/brightness'", shell=True)
    interfaces = getInterfaces()
    for wirelessInterface in interfaces:
        os.system('rfkill unblock wifi; rfkill unblock all')
        print(G + "[+] Trying interface {0}".format(wirelessInterface, ) + W)
        os.system('ifconfig {0} up'.format(wirelessInterface, ))
        # Will fail if already connected
        cells = wifi.Cell.all(wirelessInterface)

        # result_list = set([cell.ssid for cell in cells])
        # print (result_list)

        wifilist = createWifiBlacklist()
        wifilist.extend(createWifiIgnorelist())

        wifiConnected = False
        for cell in cells:
            if cell.ssid not in wifilist:
                if not cell.encrypted and str(cell.ssid):
                    wifilist.append(cell.ssid)
                    print(Y + "[*] Attempting to connect to SSID {0} on {1}".format(
                        cell.ssid, wirelessInterface, ) + W)
                    wifiConnected = attemptWiFiConnect(
                        cell.ssid, wirelessInterface)
                    if wifiConnected:
                        print(G + "[+] Successfully connected to SSID {0} on {1}".format(cell.ssid,
                                                                                         wirelessInterface, ) + W)
                        writeFile('/opt/breakout/logs/wifi.txt', time.strftime("%b %-d %H:%M:%S"), cell.ssid, "Yes",
                                  "Yes")
                        if isPi:
                            subprocess.check_output(
                                "sh -c 'echo 1 >/sys/class/leds/led0/brightness'", shell=True)
                        break
                    else:
                        print(
                            R + "[x] Failed to connect to SSID {0} on {1}".format(cell.ssid, wirelessInterface, ) + W)
                        writeFile('/opt/breakout/logs/wifi.txt', time.strftime("%b %-d %H:%M:%S"), cell.ssid, "Yes",
                                  "No")
                elif cell.ssid:
                    print(
                        B + "[-] Passing encrypted SSID {0} on {1}".format(cell.ssid, wirelessInterface, ) + W)
                    wifilist.append(cell.ssid)
                    writeFile('/opt/breakout/logs/wifi.txt',
                              time.strftime("%b %-d %H:%M:%S"), cell.ssid, "No", "No")


def getInterfaces():
    interface_list = netifaces.interfaces()
    # Get Wireless Interfaces
    return filter(lambda x: 'wl' in x, interface_list)


def writeFile(fileName, timeStamp, ssid, openStatus, connected):
    with open(fileName, 'a') as file:
        file.write("{0} {1} Open={2} Connected={3} \n".format(
            timeStamp, ssid, openStatus, connected))


def createWifiIgnorelist():
    wifiIgnorelist = []
    for ssidName in open('/opt/breakout/configs/ignore_ssid'):
        ssidName = ssidName.rstrip('\n')
        print(W + "[!] Ignoring SSID: {0}".format(ssidName, ) + W)
        wifiIgnorelist.append(ssidName)

    return wifiIgnorelist


def createWifiBlacklist():
    wifiBlacklist = []
    timeout = '30 min'

    # Audit's Wifi in the area
    answers = subprocess.check_output(
        'awk -v d1="$(date --date="-' + timeout +
        '" "+%b %_d %H:%M")" -v d2="$(date "+%b %_d %H:%M")" \'$0 > d1 && $0 < d2 || $0 ~ d2\' /opt/breakout/logs/wifi.txt | awk \'NF{NF-=2};1\' | cut -d\' \' -f4- | sort | uniq -c',
        shell=True, stderr=subprocess.STDOUT).decode('utf-8').rstrip().split('\n')
    # Will attempt to stay connected to Wifi
    # answers = subprocess.check_output('awk -v d1="$(date --date="-'+timeout+'" "+%b %_d %H:%M")" -v d2="$(date "+%b %_d %H:%M")" \'$0 > d1 && $0 < d2 || $0 ~ d2\' /opt/breakout/logs/wifi.txt | grep -v "Yes\|No Yes" |awk \'NF{NF-=2};1\' | cut -d\' \' -f4- | sort | uniq -c', shell=True, stderr=subprocess.STDOUT).rstrip().split('\n')
    try:
        for answer in answers:
            scanNum = answer.lstrip().split(' ')[0]
            ssidName = ' '.join(map(str, answer.lstrip().split(' ')[1:]))
            if not answer or int(scanNum) > 5:
                print(W + "[!] Skipping SSID {0} already scanned {1} times in {2}.".format(ssidName, scanNum,
                                                                                           timeout, ) + W)
                wifiBlacklist.append(ssidName)
    except:
        pass

    return wifiBlacklist


def main():
    # Stop if already Running
    checkRunningState("ConnectWiFi.py")

    isPi = os.path.isfile('/sys/class/leds/led1/trigger')
    try:
        currentSSID = subprocess.check_output(
            "iwgetid -r", shell=True).decode('utf-8')
        if isPi:
            subprocess.check_output(
                "sh -c 'echo 1 >/sys/class/leds/led0/brightness'", shell=True)
        print(
            G + "[+] Already connected to SSID: {0}".format(currentSSID.replace('\n', '')) + W)
    except subprocess.CalledProcessError:
        openWIFI(isPi)


if __name__ == '__main__':
    main()
