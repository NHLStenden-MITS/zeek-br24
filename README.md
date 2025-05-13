# zeek-br24
A Zeek Parser for the Navico BR24 protocol built using Spicy. 

## Overview

zeek-br24 is a Zeek plugin (written in [Spicy](https://docs.zeek.org/projects/spicy/en/latest/)) for parsing and logging fields used by the Navico BR24 protocol. This protocol is used to transmit the radar spokes to the Plot Position Indicator (PPI).The communication follows a a UDP multicast transmission with (i) the image channel carrying the raw radar image in IP 236.6.7.8 and port 6678 (ii) the register control channel carrying commands to the processor unit to adjust settings in IP 236.6.7.10 and port 6680, and (iii) the report channel carrying meta-data from the processor unit in IP 236.6.7.9 and port 6679.

The parsing logic of this parser was developed based on the [OpenCPN radarpi plugin](https://github.com/opencpn-radar-pi/radar_pi/tree/master/src/navico), which serves as a source of information for the [Wireshark dissector](README.md) (see [Resources](#resources)).

This parser produces one log file, `br24.log`, defined under [scripts/main.zeek](./scripts/main.zeek).

The [Logging Capabilities](#loggingcapabilities) section below provides more details for the current fields that are supported.

## Installation

To build and install the parser into Zeek the following can be used:

```
$ cd zeek-br24
$ cmake . && make install
$ zeek -NN | grep BR24
```

## Logging Capabilities

### Navico BR24 Log (br24.log)

This parser and the corresponding Zeek main file, capture and log each BR24 message transmitted over UDP ports 6678, 6679 and 6680 to `br24.log`.

There are three categories of data that are transmitted via BR24 (i) Image Data, (ii) Reports and (iii) Registers. Below there is a list of the currently implemented functionality.


**Image Data**

| Reference         | Implemented           |
| ----------------- |-----------------------|
|Frame Header       |x                      |
|Scanline Header    |x                      |
|Scanline Pixels    |x                      |

**Reports** -
**0xC4 Reports**
| Reference         | Implemented           |
| ----------------- |-----------------------|
|Status             |x                      |
|Settings           |x                      |
|Firmware           |x                      |
|Bearing            |x                      |
|05 Report - Undocumented            |x     |
|07 Report - Undocumented            |x     |
|Scan               |x                      |

**0xF5 Reports**
| Reference         | Implemented           |
| ----------------- |-----------------------|
|Undocumented       |x                      |


**Registers** -
| Reference         | Implemented           |
| ----------------- |-----------------------|
| Radar Status      |x                      |
| Zoom Level        |x                      |
| Bearing Alignment |x                      |
| Filters and Preprocessing        |x       |
| Interference Rejection        |x          |
| Target Expansion        |x                |
| Target Boost            |x                |
| Local Interference Filter            |x   |
| Scan Speed        |x                      |
| Antenna Height    |x                      |
| Keep Alive        |x                      |

## Resources

Various resources that assist to the development of this parser.

* Wireshark Navico BR24 dissector documentation: https://github.com/fkie-cad/maritime-dissector/blob/master/docs/protocols.md 
* OpenCPN radarpi plugin: https://github.com/opencpn-radar-pi/radar_pi/tree/master/src/navico
* OpenBR24: https://github.com/sonole/OpenBR24
* Paper from: Adrian Dabrowski, Sebastian Busch, and Roland Stelzer. "A digital interface for imagery and control of a Navico/Lowrance broadband radar." Robotic Sailing. Springer, Berlin, Heidelberg, 2011. 169-181, DOI: [10.1007/978-3-642-22836-0_12](https://www.researchgate.net/publication/226363952_A_Digital_Interface_for_Imagery_and_Control_of_a_NavicoLowrance_Broadband_Radar)


## PCAPs

The PCAP used to create this parser can be found under [Traces](./testing/Traces/). This has been acquired from the [OpenCPN radarpi plugin](https://github.com/opencpn-radar-pi/radar_pi/tree/master/example) GitHub repository. Another collection of PCAPs used for security research, can be found in the [RadarPWN](https://doi.org/10.5281/zenodo.7188636) data repository.

From such captures, streams for one type of BR24 data such as image data can be extracted as files (e.g., test_IMG_only.pcapng) to test the individual functionality. Those have not been included here to avoid duplication.

## Streams

The streams for the used PCAPs are created using ``zeek -C -r <path to PCAP> udp-contents``, where the udp-contents comes from: https://docs.zeek.org/projects/spicy/en/v1.11.3/tutorial/ .

## How to contribute?

You can find more information in [CONTRIBUTING](./CONTRIBUTING.md)
