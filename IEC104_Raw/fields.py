#!/usr/bin/env python3

# Copyright (c) 2019 Neil Ortiz, nortizsi@ucsc.edu
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

import struct
from scapy.config import conf
from scapy.packet import Packet
from scapy.fields import Field, StrField, XByteField, ByteField, PacketField

class LEFloatField(Field):
    '''
    little-endian float
    '''
    def __init__(self, name, default):
        Field.__init__(self, name, default, '<f')

class SignedShortField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "<h")

class IOAID(Field):

    def __init__(self, name, default):
        Field.__init__(self, name, default, '<I')

    def addfield(self, pkt, s, val):
        value = []
        value[0] = int(val & 0xff)
        value[1] = int((val & 0xff00) / 0x0100)
        value[2] = int((val & 0xff0000) / 0x010000)
        # return s + struct.pack('BBB', value[0], value[1], value[2])
        return s + struct.pack('BB', value[0], value[1]) # NOTE: For malformed packets
 

    def getfield(self, pkt, s):
        # return s[3:], self.m2i(pkt, struct.unpack(self.fmt, s[:3] + b'\x00')[0]) 
        return s[2:], self.m2i(pkt, struct.unpack(self.fmt, s[:2] + b'\x00\x00')[0]) # NOTE: For malformed packets
 
