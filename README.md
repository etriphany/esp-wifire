
<h1 align="center">ESP Wifire</h1>
<p align="center">
    <img src="https://raw.githubusercontent.com/etriphany/esp-wifire/master/docs/img/esp01.jpeg" height="225"/>
    <img src="https://raw.githubusercontent.com/etriphany/esp-wifire/master/docs/img/fire.png" height="225"/>
</p>
<h3 align="center">Use it with responsability, its not a toy!</h3>

# Project Proposal
This project is proposed to offer some experiments related with [Wifi frames](https://en.wikipedia.org/wiki/Cracking_of_wireless_networks), that can be used to perform security related operations.

It was created to be:

* Full based on [Espressif NonOS](https://www.espressif.com/en/support/download/sdks-demos)
* Self contained, no external libraries
* Minimal IO, for minimal ESP8266 (_ESP01_)

# Features
* Access Point Scanner
* Packet Sniffer
* PCAP Serializer
* Client Deauthentication
* Network Spam
* Probe-Request Spam


# ESP8266 selection

To change the ESP8266 chip version:

- ESP01 (1MB flash): `#define ESP01` (out-of-the-box)
- ESP12 (4MB flash): `#define ESP12`


# Serial port mode

To change the serial port mode:

- PCAP pipe: (out-of-the-box)
- Printer: `#define PRINTER_MODE`


# Flashing

 If you use `push-button` programmer circuits, you will need to adjust `esptool.py` calls in the Makefile,including the option **--before no_reset**.

 Example:

 ```Makefile
  $(ESPTOOL) --chip esp8266 --port $(ESPPORT) --before no_reset write_flash ...

 ```
> Now after executing a Make command, simply do the manual reset (by pushing Flash/Reset) and everything will work like a charm!

# Inspired by

- [ESP8266 Deauther](https://github.com/spacehuhn/esp8266_deauther)

- [ESP8266 Simple Sniffer](https://github.com/n0w/esp8266-simple-sniffer)