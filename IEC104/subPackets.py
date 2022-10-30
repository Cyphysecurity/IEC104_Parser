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

from struct import unpack
from scapy.fields import XByteField, LEShortField, StrField, PacketField
from scapy.packet import Packet, Padding, conf
from .const import *
from .ioa import IOAS, IOALEN
    
class ApciTypeI(Packet):

    name = 'APCI Type I'
    fields_desc = [
        XByteField('type', 0x00),
        LEShortField('Tx', 0x0000),
        LEShortField('Rx', 0x0000)
    ]

    def do_dissect(self, s):
        self.type = 0x00
        self.Tx = int((s[0] & 0xfe) / 2) + (s[1] * 0x80)
        self.Rx = int((s[2] & 0xfe) / 2) + (s[3] * 0x80)
        return s[4:]

class ApciTypeS(Packet):
    name = 'APCI Type S'
    fields_desc = [
        StrField('Type', None),
        LEShortField('Rx', 0x0000)
    ]

    def do_dissect(self, s):
        flags_Type = s[0] & 0x03
        self.Type = TYPE_APCI[flags_Type]
        self.Rx = int((s[2] & 0xfe) / 2) + (s[3] * 0x80)
        return s[4:]

    def dissect(self, s):
        s = self.pre_dissect(s)
        s = self.do_dissect(s)
        s = self.post_dissect(s)
        payl,pad = self.extract_padding(s)
        self.do_dissect_payload(payl)
        if pad and conf.padding:
            self.add_payload(Padding(pad))

class ApciTypeU(Packet):
    name = 'APCI Type U'
    fields_desc = [
        StrField('Type', None),
        StrField('UType', None)
    ]

    def do_dissect(self, s):
        flags_Type = s[0] & 0x03
        self.Type = TYPE_APCI[flags_Type]
        flags_UType = s[0] & 0xfc
        self.UType = UNNUMBERED_CONTROL_FIELD[flags_UType]
        return s[4:]

    def dissect(self, s):
        s = self.pre_dissect(s)
        s = self.do_dissect(s)
        s = self.post_dissect(s)
        payl,pad = self.extract_padding(s)
        self.do_dissect_payload(payl)
        if pad and conf.padding:
            self.add_payload(Padding(pad))

class ApciType(StrField):

    def m2i(self, pkt, x):
        ptype = x[0] & 0x03
        if ptype in [0x00, 0x02]:
            return ApciTypeI(x)
        elif ptype == 0x01:
            return ApciTypeS(x)
        else:
            return ApciTypeU(x)

    def addfield(self, pkt, s, val):
        return s + self.i2m(pkt, val)
    
    def getfield(self, pkt, s):
        return s[4:], self.m2i(pkt, s[:4])
     
