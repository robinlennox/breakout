#!/usr/bin/python
# By Robin Lennox - twitter.com/robberbear

import os
import time

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from pexpect import pxssh
from lib.layout import *

#Import Colour Scheme
G,Y,B,R,W = colour()

def openPort(port,ip):
	try:
		response = sr1(IP(dst=ip)/TCP(dport=port, flags="S"),verbose=False, timeout=2)
		while response:
			if response[TCP].flags == 18 :
				return True
			else:
				return False
	except:
		return False

def icmpTunnelAttempt(ip,PWD):
	answer = subprocess.check_output(PWD+'/icmp_tunnel_client.sh %s' %(ip), shell=True)
	return answer

def icmpTunnel(ipAddr,verbose):
	count = 0
	stopCount = 5
	PWD=os.path.dirname(os.path.realpath(__file__))
	os.chmod(PWD+'/icmp_tunnel_client.sh', 0o655)
	response = sr1(IP(dst="10.0.0.1")/TCP(dport=22, flags="S"),verbose=False, timeout=1)
	while (count < stopCount):
			if verbose:
				print B+"[-] Attempting ICMP Tunnel"+W
			time.sleep(5)
			if '0' in icmpTunnelAttempt(ipAddr,PWD):
				return True
				break
			else:
				# Restricts Attempts
				count = count + 1
	return False

def checkTunnel(ipAddr,portNumber):
	failedMessage=R+"[x] Failed connect, trying again."+W
	s = pxssh.pxssh(timeout=10,) #Timeout 10 is used for RAW DNS Tunnel as this is slow to connect.
	try:
		testConn = s.login (ipAddr, 'myusername', 'mypassword', port=portNumber,auto_prompt_reset=False)
		s.close()
		# Should never get here
		#print s.login (ipAddr, 'myusername', 'mypassword', auto_prompt_reset=False)
		#print "failedMessage"
		#return False
	except pxssh.ExceptionPxssh, e:
			# DNS Tunnel setup but not routable.
			if "could not set shell prompt" in str(e):
				print failedMessage
				#print str(e)
				return False
			else:
				print G+"[+] SSH Tunnel Created!"+W
				#print str(e)
				return True
	except:
		# Catch all
		print failedMessage
		return False

def callIodine(switch,password,nameserver,verbose,timeout,):
	os.system('sudo iodine -f -P %s 8.8.8.8 %s %s > /dev/null 2>&1 &' %(password,nameserver,switch,))
	time.sleep(timeout)
	return checkTunnel('192.168.128.1',22)

def dnsTunnel(password,nameserver,verbose,):
	count = 0
	stopCount = 1
	while (count < stopCount):
		if callIodine('-O RAW',password,nameserver,verbose,30):
			print B+"[-] DNS Tunnel using RAW Mode Setup."+W
			return True
			count = stopCount
		else:
			os.system('sudo killall iodine > /dev/null 2>&1')
			count = count + 1
	
	# Fallback try RAW
	if callIodine('-r -I1',password,nameserver,verbose,100):
		print B+"[-] DNS Tunnel straight to callback server setup (Very Slow)."+W
		print B+"[-] An DNS Tunnel the server is not as fast as a RAW Tunnel"+W
		return True
	else:
		os.system('sudo killall iodine > /dev/null 2>&1')