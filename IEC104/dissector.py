#!/usr/bin/env python3

"""
Version: 1.2
Date: 10/29/2022
"""

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
from struct import unpack, pack
from scapy.packet import Raw, bind_layers, Padding, Packet, conf
from scapy.layers.inet import TCP
from scapy.fields import XByteField, ByteField, PacketListField, ByteEnumField, PacketField
from .subPackets import ApciType
from .ioa import IOAS, IOALEN
from .const import SQ, CAUSE_OF_TX, TYPEID_ASDU
from scapy.all import conf

class ASDU(Packet):

    name = 'IEC 60870-5-104-Asdu'
    fields_desc = [
        ByteField('TypeId',None),
        ByteField('SQ',None),
        ByteField('NumIx',0),
        ByteEnumField('CauseTx',None, CAUSE_OF_TX),
        ByteField('Negative',False),
        ByteField('Test', None),
        ByteField('OA',None),
        ByteField('Addr',None),
        PacketListField('IOA', None)
    ]

    def do_dissect(self, s):
        try:
            self.TypeId = TYPEID_ASDU[s[0] & 0xff]
        except Exception:
            self.TypeId = 'Undefined'
            return
        typeId = s[0] & 0xff
        flags_SQ = s[1] & 0x80
        
        self.SQ =  SQ[flags_SQ]
        self.NumIx = s[1] & 0x7f
        self.CauseTx = s[2] & 0x3F
        self.Negative = SQ[s[2] & 0x40] 
        self.Test = SQ[s[2] & 0x80]
        self.OA = s[3]
        self.Addr = unpack('<H',s[4:6])[0]

        flag=True
        list_IOA = list()
        remain = s[6:]
        
        idx=6
        i=1
        typeIOA = IOAS[typeId]
        lenIOA=IOALEN[typeId]
        j=0
        if self.SQ:
            for i in range(1,self.NumIx+1):
                if flag:
                    list_IOA.append(typeIOA(remain[:lenIOA]))
                    offset= list_IOA[0].IOA
                    remain = remain[lenIOA:]
                    idx = idx+lenIOA
                    lenIOA = lenIOA-3
                else:
                    offsetIOA = pack("<H",(i-1)+offset)+b'\x00' # See 7.2.2.1 of IEC 60870-5-101 
                    remain2 = offsetIOA + remain[:lenIOA]
                    list_IOA.append(typeIOA(remain2))
                    remain = remain[lenIOA:]
                    idx = idx+lenIOA
                flag=False
        else:
            for i in range(1,self.NumIx+1):
                list_IOA.append(typeIOA(remain[:lenIOA])) 
                remain = remain[lenIOA:]
                idx= idx+lenIOA
        self.IOA = list_IOA
        return s[idx:]

    def extract_padding(self, s):
        return None, s

class APCI(Packet):

    name = 'IEC 60870-5-104-Apci'

    fields_desc = [
        XByteField('START',0x68),
        ByteField('ApduLen',4),
        ApciType('Apci', None),
    ]

    def extract_padding(self, s):
        return None, s

class APDU(Packet):
    name = 'APDU'
    fields_desc = [
        PacketField('APCI', None, APCI),
        PacketField('ASDU', None, ASDU)
    ]

    def dissect(self, s):
        s = self.pre_dissect(s)
        s = self.do_dissect(s)
        s = self.post_dissect(s)
        payl,pad = self.extract_padding(s) 
        self.do_dissect_payload(payl)
        if pad and conf.padding:
            if pad[0] in [0x68]:
                self.add_payload(APDU(pad))
            else:
                self.add_payload(Padding(pad))

    def extract_padding(self, s):
        return '', s

bind_layers(TCP, APDU, sport=2404)
bind_layers(TCP, APDU, dport=2404)
