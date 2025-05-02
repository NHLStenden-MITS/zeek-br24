# zeek-br24
A Zeek Parser for the Navico BR24 protocol built using Spicy. 

## Overview

zeek-br24 is a Zeek plugin (written in [Spicy](https://docs.zeek.org/projects/spicy/en/latest/)) for parsing and logging fields used by the Navico BR24 protocol. This protocol is used to transmit the radar spokes to the Plot Position Indicator (PPI).The communication follows a a UDP multicast transmission with (i) the image channel carrying the raw radar image in IP 236.6.7.8 and port 6678 (ii) the register control channel carrying commands to the processor unit to adjust settings in IP 236.6.7.10 and port 6680, and (iii) the report channel carrying meta-data from the processor unit in IP 236.6.7.9 and port 6679.

The parsing logic of this plugin was developed based on the [OpenCPN radarpi plugin](https://github.com/opencpn-radar-pi/radar_pi/tree/master/src/navico), which serves as a source of information for the [Wireshark dissector](README.md) (see [Resources](#resources)).

This parser produces one log file, `br24.log`, defined under [scripts/main.zeek](./scripts/main.zeek).

The *Logging Capabilities* section below provides more details for the current fields that are supported.

## Installation

To build and install the parser into Zeek the following can be used:

```
$ cd zeek-br24
$ cmake . && make install
$ zeek -NN | grep br24
```

## Logging Capabilities

### Navico BR24 Log (br24.log)

This parser and the corresponding Zeek main file, capture and log each BR24 message transmitted over UDP ports 6678, 6679 and 6680 to `br24.log`.

TODO

## Resources

Various resources that assist to the development of this parser.

TODO

## PCAPs

TODO

## Streams

The streams for the above PCAPs are created using ``zeek -C -r <path to PCAP> Conn::default_extract=T``.

## How to contribute?

TODO
