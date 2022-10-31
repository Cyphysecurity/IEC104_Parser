#!/usr/bin/env python3

from scapy.all import Ether
from IEC104.dissector import APDU
from IEC104.subPackets import *
from binascii import unhexlify


data = unhexlify('00090f09020778da6ee36360080045000047661240007e06abe9c0a86f61c0a8fa020964e3f2f642b3492ad216c68018ffeded4500000101080a2dce185fb7c4721b6811023002000d010300e4003f0251a7654300')
Ether(data).show()
