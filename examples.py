#!/usr/bin/env python3

from scapy.all import Ether
from IEC104.dissector import APDU
from IEC104.subPackets import *
from binascii import unhexlify


data = unhexlify('6812aaf380150d0103000114eb030017ad304300')
Ether(data).show()
