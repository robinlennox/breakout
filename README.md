# Breakout
![alt tag](https://github.com/robinlennox/breakout/images/Breakout_logo.png)
![GPLv3 License](https://img.shields.io/badge/License-GPLv3-red.svg) [![Python 2.6|2.7](https://img.shields.io/badge/python-2.6|2.7-yellow.svg)](https://www.python.org/) [![Twitter Follow](https://img.shields.io/twitter/follow/robberbear.svg?style=social&label=@robberbear)](https://twitter.com/robberbear)

Breakout was built to allow a device to get access to the internet on a restricted network by trying to find an open port on the firewall, making a ICMP Tunnel or a DNS Tunnel.

This tools could be used on a device which is dropped on a client's network, which automatically breakout to the internet. If successful, the device can be used for reconnaissance and as a pivot onto other devices on the network.

Alternatively, you could use it to circumvent an organisations proxy or Wi-Fi Paywalls!

## Documentation

See the [Wiki](https://github.com/robinlennox/breakout/wiki/) for documentation, [installation guides](https://github.com/robinlennox/breakout/wiki/Installation), [examples](https://github.com/robinlennox/breakout/wiki/Examples) and other information.

### Tested On
Ubuntu 16.04 Server

#### Disclaimer
This tool is only for academic purposes and testing under controlled environments. Do not use without obtaining proper authorisation from the network owner of the network under testing.

The author bears no responsibility for any misuse of the tool.

### Credits
The following tools are used in Breakout:
* [icmptunnel](https://github.com/jamesbarlow/icmptunnel) implementation by James Barlow.
* [iodine](https://github.com/yarrick/iodine) implementation by Erik Ekman.
