# Breakout
![alt tag](https://github.com/robinlennox/breakout/blob/master/images/Breakout_logo.png)
![GPLv3 License](https://img.shields.io/badge/License-GPLv3-red.svg) [![Twitter Follow](https://img.shields.io/twitter/follow/robberbear.svg?style=social&label=@robberbear)](https://twitter.com/robberbear)

Breakout was built to allow a device to get access to the internet on a restricted network by trying to find an open port on the firewall, making a ICMP Tunnel or a UDP Tunnel.

This tool could be used on a device which is dropped on a client's network, which automatically breaks out to the internet. If successful, the device can be used for reconnaissance, as a pivot onto other devices on the network and so on.

## Documentation

See the [Wiki](https://github.com/robinlennox/breakout/wiki/) for documentation, [installation guides](https://github.com/robinlennox/breakout/wiki/Installation), [examples](https://github.com/robinlennox/breakout/wiki/Examples) and other information.

## Credits
The following tools are used in Breakout:
* [icmptunnel](https://github.com/jamesbarlow/icmptunnel) implementation by James Barlow.
* [kcptun](https://github.com/xtaci/kcptun) implementation by wangyu-.
* [udp2raw-tunnel](https://github.com/wangyu-/udp2raw-tunnel) implementation by xtaci.

## Disclaimer
This tool is only for academic purposes and testing under controlled environments. Do not use without obtaining proper authorisation from the network owner of the network under testing.

The author takes no responsibility for any misuse of this tool.