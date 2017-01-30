# BLESDR

Bluetooth Low Energy SDR C++ Library

Features
--------
Decode IQ samples to BLE Packet
IQ samples generator from BLE Packet

Example
-------
example only support LimeSDR now

 1. BLE Sniffer

 > blesdr -S
 
> 1485756493.576926 ,Address: 0x8E89BED6,CRC:0x0BFF03 ,Packet Length:38
Data:40 24 10 BE A5 24 62 60 02 01 1A 1A FF 4C 00 02 15 FD A5 06 93 A4 E2 4F B1 AF CF C6 EB 07 64 78 25 00 0A 00 07 C5

 2. iBeacon Advertising

> blesdr -b B9407F30F5F8466EAFF925556B57FE6D -m 1.2

 3. Replay BLE Packet

> blesdr -R

 
References
---------
[https://github.com/floe/BTLE][1]
[https://github.com/JiaoXianjun/BTLE][2]
[https://github.com/omriiluz/NRF24-BTLE-Decoder][3]


  [1]: https://github.com/floe/BTLE
  [2]: https://github.com/JiaoXianjun/BTLE
  [3]: https://github.com/omriiluz/NRF24-BTLE-Decoder