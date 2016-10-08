# Breakout 
![GPLv3 License](https://img.shields.io/badge/License-GPLv3-red.svg)
[![Python 2.6|2.7](https://img.shields.io/badge/python-2.6|2.7-yellow.svg)](https://www.python.org/)

Breakout was built to allow a device to get access to the internet on a restricted network by trying to find an open port on the firewall, making a ICMP Tunnel or a DNS Tunnel.

This tools could be used on a device which is dropped on a client's network, then automatically attempts to breakout to the internet. If successful, the device can be remotely managed and used for reconnaissance.

Alternatively, you could use it to circumvent an organisations proxy or Wifi Paywalls!

### Tested On
Ubuntu 16.04 Server

#### Disclaimer
This tool is only for academic purposes and testing under controlled environments. Do not use without obtaining proper authorisation from the network owner of the network under testing.
The author bears no responsibility for any misuse of the tool.

### Credits
The following tools are used in Breakout:
* [icmptunnel](https://github.com/jamesbarlow/icmptunnel) implementation by James Barlow.
* [iodine](https://github.com/yarrick/iodine) implementation by Erik Ekman.

### Notes
Running in aggressive can cause and IPS to kick in so use this as a last resort.

#### Usage
To get a list of all options and switches use:

```sh
sudo python breakout.py -h
```

#### Examples
Find paths to breakout to the internet.
```sh
sudo python breakout.py                                                              
```
Callback to server on the internet.
```sh
sudo python breakout.py -c 1.2.3.4
```
Use aggressive mode.
```sh
sudo python breakout.py -A
```
Callback to server with DNS Tunnel details.
```
sudo python breakout.py -c 1.2.3.4 -p breakout -n tunnel.mywebsite.com -v     
```

## Installation
Breakout is installed by running the following commands in your terminal.

### On Server

```shell
bash -c "$(wget https://raw.githubusercontent.com/robinlennox/breakout/master/lib/setup/install_server.sh -O -)"
```

### On Client
```shell
bash -c "$(wget https://raw.githubusercontent.com/robinlennox/breakout/master/lib/setup/install_client.sh -O -)"
```

### Setting up DNS Tunnel
Two DNS Records need to be created. It doesn't matter about the sames, however the FQDN which the NS resolves to much match the A record name, in this instance tunnel.

```
iodine      IN  NS  tunnel.mywebsite.om.
tunnel      IN  A   1.2.3.4
```

### Speed of Tunnels
This is based of a quick test I performed over Wifi.
#### No Tunnel
* Speed around 12.2Mbps Down and 4Mbps Up.

#### ICMP Tunnel
* Speed around 350kBits Down and 20kBits Up.  (Can watch 240p Youtube video)

#### DNS Tunnel 
* Using RAW Mode - speed around 1.5MBits Down and 0.5MBits Up. (Can watch 720p Youtube video)
* Not using RAW mode - speed around 15kBits Down and 3kBits Up. (Can just use ssh.. just)
