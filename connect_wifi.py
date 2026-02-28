#!/usr/bin/env python
# By Robin Lennox - twitter.com/robberbear

import netifaces
import subprocess
import os
import time

import wifi

from lib.ScriptManagement import checkRunningState
from lib.Layout import colour

import configparser

config = configparser.ConfigParser()
config.read('/opt/breakout/lib/config.ini')

# Import Colour Scheme
G, Y, B, R, W = colour()


def attemptWiFiConnect(ssidName, wirelessInterface):
    count = 1
    stopCount = 5
    status = False
    command = "rfkill unblock wifi; rfkill unblock all;"
    subprocess.Popen(command.split(), stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE)
    subprocess.check_output("ifconfig {0} down".format(wirelessInterface, ), shell=True,
                            stderr=subprocess.STDOUT).decode('utf-8')
    subprocess.check_output("iwconfig {0} essid any".format(wirelessInterface, ), shell=True,
                            stderr=subprocess.STDOUT).decode('utf-8')
    subprocess.check_output("ifconfig {0} up".format(wirelessInterface, ), shell=True, stderr=subprocess.STDOUT).decode(
        'utf-8')
    subprocess.check_output("iwconfig {0} essid \"{1}\"".format(wirelessInterface, ssidName, ), shell=True,
                            stderr=subprocess.STDOUT).decode('utf-8')
    # Allow the interface to come backup
    print(
        B + "[-] Waiting for network to finish setting up" + W)
    subprocess.check_output("dhcpcd -i {0}".format(wirelessInterface), shell=True,
                            stderr=subprocess.STDOUT).decode('utf-8')
    waitTime = config.getint('WIFI', 'WAITTIME')
    time.sleep(waitTime)

    while (count < stopCount and status == False):
        if getCurrentSSID() is not None:
            status = True
        else:
            count = count + 1
            if count == stopCount:
                print(
                    Y + "[*] Failed to get DHCP address for SSID {0} on {1}".format(ssidName, wirelessInterface, ) + W)
                print(
                    R + "[x] Try disabling network management of host such as 'sudo service network-manager stop'\n" + W)

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
    timeout = 180000

    # Audit's Wifi in the area
    answers = subprocess.check_output(['awk -v d1="$(date -d@"$(( $(date +%s)-{0}))" "+%b %_d %H:%M")" -v d2="$(date "+%b %_d %H:%M")" \'$0 > d1 && $0 < d2 || $0 ~ d2\' /opt/breakout/logs/wifi.txt | awk \'{{print $4}}\' | sort | uniq -c'.format(timeout)]
        ,shell=True, stderr=subprocess.STDOUT).decode('utf-8').rstrip().lstrip()
    try:
        if len(answers) > 1:
            answers = answers.split('\n')
            for answer in answers:
                scanNum = answer.lstrip().split(' ')[0]
                ssidName = ' '.join(map(str, answer.lstrip().split(' ')[1:]))
                if not answer or int(scanNum) > 5:
                    print(W + "[!] Skipping SSID {0} already scanned {1} times in {2} minutes".format(ssidName, scanNum,
                                                                                            str(timeout/60), ) + W)
                    wifiBlacklist.append(ssidName)
    except:
        pass

    return wifiBlacklist


def getCurrentSSID():
    currentSSID = subprocess.check_output("iwconfig 2> /dev/null | awk -F\\\" \'{print $2}\'", shell=True).decode('utf-8').replace('\n', '')
    if not currentSSID:
        currentSSID = None
    time.sleep(config.getint('WIFI', 'WAITTIME'))
    return currentSSID

def main():
    # Stop if already Running
    checkRunningState("ConnectWiFi.py")

    isPi = os.path.isfile('/sys/class/leds/led1/trigger')
    try:
        currentSSID = getCurrentSSID()
        if currentSSID is not None:
            print(
                G + "[+] Already connected to SSID: {0}".format(currentSSID) + W)
            if isPi:
                subprocess.check_output(
                    "sh -c 'echo 1 >/sys/class/leds/led0/brightness'", shell=True)
        else:
            openWIFI(isPi)

    except subprocess.CalledProcessError:
        openWIFI(isPi)


if __name__ == '__main__':
    if config.getboolean('WIFI', 'CONNECTWIFI') is True:
        main()
    else:
        print(W + "[!] Config: Skipping Wifi Auto Connect" + W)
