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
from scapy.fields import PacketField, ShortField
from .fields import IOAID, LEFloatField, ByteField, SignedShortField
from .const import OV, BL, SB, NT, IV, SU, DOW, SE, DPI, TRANSIENT, QOi, SPI, R, I
from scapy.packet import Packet

class BSI(Packet):
    name = 'BSI'
    fields_desc = [
        ShortField('BSI',None),
    ]

    def do_dissect(self, s):
        self.BSI = ''.join(format(bt, '08b') for bt in s[0:4])
        return s[4:]
    
    def extract_padding(self, s):
        return '', s

class COI(Packet):
    name = 'COI'
    fields_desc = [
        ByteField('R',None),
        ByteField('I',None),
    ]

    def do_dissect(self, s):
        try:
            self.R = R[s[0] & 0x7F]
        except Exception:
            self.R = 'undefine'
        self.I = I[s[0] & 0x80]
        return s[1:]
    
    def extract_padding(self, s):
        return '', s

class SIQ(Packet):
    name = 'SIQ'
    fields_desc = [
        ByteField('SPI',None),
        ByteField('BL',None),
        ByteField('SB',None),
        ByteField('NT',None),
        ByteField('IV',None)
    ]

    def do_dissect(self, s):
        self.SPI = SPI[s[0] & 0x01]
        self.BL = BL[s[0] & 0x10]
        self.SB = SB[s[0] & 0x20]
        self.NT = NT[s[0] & 0x40]
        self.IV = IV[s[0] & 0x80]
        return s[1:]
    
    def extract_padding(self, s):
        return '', s

class QOI(Packet):
    name = 'QOI'
    fields_desc = [
        ByteField('QOI',None),
    ]

    def do_dissect(self, s):
        self.QOI = QOi[s[0]]
        return s[1:]
    
    def extract_padding(self, s):
        return '', s

class VTI(Packet):
    name = 'VTI'
    fields_desc = [
        ByteField('Value',False),
        ByteField('Transient',None)
    ]

    def do_dissect(self, s):
        self.Value = unpack("<B", bytes([s[0] & 0x7F]))[0]
        self.Transient = TRANSIENT[s[0] & 0x80] 

        return s[1:]
    
    def extract_padding(self, s):
        return '', s

class DIQ(Packet):
    name = 'QDS'
    fields_desc = [
        ByteField('DPI',False),
        ByteField('BL',None),
        ByteField('SB',None),
        ByteField('NT',None),
        ByteField('IV',None)
    ]

    def do_dissect(self, s):
        self.DPI = DPI[s[0] & 0x03]
        self.BL = BL[s[0] & 0x10]
        self.SB = SB[s[0] & 0x20]
        self.NT = NT[s[0] & 0x40]
        self.IV = IV[s[0] & 0x80]

        return s[1:]
    
    def extract_padding(self, s):
        return '', s

class QOS(Packet):
    name = 'QDS'
    fields_desc = [
        ByteField('QL',False),
        ByteField('SE',None)
    ]

    def do_dissect(self, s):
        self.QL = s[0] & 0x7F
        self.SE = SE[s[0] & 0x10]

        return s[1:]
    
    def extract_padding(self, s):
        return '', s

class QDS(Packet):
    name = 'QDS'
    fields_desc = [
        ByteField('OV',False),
        ByteField('BL',None),
        ByteField('SB',None),
        ByteField('NT',None),
        ByteField('IV',None)
    ]

    def do_dissect(self, s):
        self.OV = OV[s[0] & 0x01]
        self.BL = BL[s[0] & 0x10]
        self.SB = SB[s[0] & 0x20]
        self.NT = NT[s[0] & 0x40]
        self.IV = IV[s[0] & 0x80]

        return s[1:]
    
    def extract_padding(self, s):
        return '', s

class CP56Time(Packet):

    name = 'CP56Time'
    fields_desc = [
        ByteField('MS',None),
        ByteField('Min',None),
        ByteField('IV',None),
        ByteField('Hour',None),
        ByteField('SU',None),
        ByteField('Day',None),
        ByteField('DOW',None),
        ByteField('Month',None),
        ByteField('Year',None),
    ]

    def do_dissect(self, s):
        self.MS = unpack('<H',s[0:2])[0]
        self.Min = int(s[2] & 0x3f)
        self.IV = IV[s[2] & 0x80]
        self.Hour = int(s[3] & 0x1F)
        self.SU = SU[s[3] & 0x80]
        self.Day = int(s[4] & 0x1F)
        self.DOW = DOW[s[4] & 0xE0]
        self.Month = int(s[5] & 0x0F)
        self.Year = int(s[6] & 0x7F)
        return s[7:]
    
    def extract_padding(self, s):
        return '', s

class IOA36(Packet):

    name = 'IOA'
    fields_desc = [
        IOAID('IOA', None),
        LEFloatField('Value', None),
        PacketField('QDS', None, QDS),
        PacketField('CP56Time', None, CP56Time),
    ]

    def extract_padding(self, s):
        return '', s

class IOA13(Packet):
    name = 'IOA'
    fields_desc = [
        IOAID('IOA', None),
        LEFloatField('Value', None),
        PacketField('QDS', None, QDS)
    ]

    def extract_padding(self, s):
        return '', s

class IOA9(Packet):
    name = 'IOA'
    fields_desc = [
        IOAID('IOA', None),
        SignedShortField('Value', None),
        PacketField('QDS', None, QDS)
    ]

    def extract_padding(self, s):
        return '', s

class IOA50(Packet):
    name = 'IOA'
    fields_desc = [
        IOAID('IOA', None),
        LEFloatField('Value', None),
        PacketField('QOS', None, QOS)
    ]

    def extract_padding(self, s):
        return '', s

class IOA3(Packet):
    name = 'IOA'
    fields_desc = [
        IOAID('IOA', None),
        PacketField('DIQ', None, DIQ)
    ]

    def extract_padding(self, s):
        return '', s

class IOA5(Packet):
    name = 'IOA'
    fields_desc = [
        IOAID('IOA', None),
        PacketField('VTI', None, VTI),
        PacketField('QDS', None, QDS)
    ]

    def extract_padding(self, s):
        return '', s

class IOA100(Packet):
    name = 'IOA'
    fields_desc = [
        IOAID('IOA', None),
        PacketField('QOI', None, QOI)
    ]

    def extract_padding(self, s):
        return '', s

class IOA103(Packet):
    name = 'IOA'
    fields_desc = [
        IOAID('IOA', None),
        PacketField('CP56Time', None, CP56Time)
    ]

    def extract_padding(self, s):
        return '', s

class IOA30(Packet):
    name = 'IOA'
    fields_desc = [
        IOAID('IOA', None),
        PacketField('SIQ', None, SIQ),
        PacketField('CP56Time', None, CP56Time)
    ]

    def extract_padding(self, s):
        return '', s

class IOA70(Packet):
    name = 'IOA'
    fields_desc = [
        IOAID('IOA', None),
        PacketField('COI', None, COI)
    ]

    def extract_padding(self, s):
        return '', s

class IOA31(Packet):
    name = 'IOA'
    fields_desc = [
        IOAID('IOA', None),
        PacketField('DIQ', None, DIQ),
        PacketField('CP56Time', None, CP56Time)
    ]

    def extract_padding(self, s):
        return '', s

class IOA1(Packet):
    name = 'IOA'
    fields_desc = [
        IOAID('IOA', None),
        PacketField('SIQ', None, SIQ)
    ]

    def extract_padding(self, s):
        return '', s

class IOA7(Packet):
    name = 'IOA'
    fields_desc = [
        IOAID('IOA', None),
        PacketField('BSI', None, BSI),
        PacketField('QDS', None, QDS)
    ]

    def extract_padding(self, s):
        return '', s

IOAS = {
    36: IOA36,
    13: IOA13,
    9: IOA9,
    50: IOA50,
    3: IOA3,
    5: IOA5,
    100: IOA100,
    103: IOA103,
    30: IOA30,
    70: IOA70,
    31: IOA31,
    1: IOA1,
    7: IOA7,
}

IOALEN = {
    36: 15,
    13: 7, # NOTE: For malformed packets 
    # 13: 8,
    9: 6,
    50: 8,
    3: 4,
    5: 5,
    100: 4,
    103: 10,
    30: 11,
    70: 4,
    31: 11,
    1: 4,
    7: 8,
}
