#!/usr/bin/env python3

from struct import unpack
from scapy.fields import PacketField, LEShortField, ShortField, FlagsField, ByteEnumField, BitEnumField, BitField, XIntField, LEIntField
from .fields import IOAID, LEFloatField, ByteField, SignedShortField # pylint: disable= import-error
from .const import QDS_FLAGS, SU, DOW_ENUM, SEL_EXEC, DPI_ENUM, DIQ_FLAGS, SIQ_FLAGS, TRANSIENT, QOI_ENUM, R_ENUM, I_ENUM, QU_ENUM, SEL_EXEC, SCS_ENUM # pylint: disable= import-error
from scapy.packet import Packet

class COI(Packet):
    name = 'COI'
    fields_desc = [
        BitEnumField('I', None, 1, I_ENUM),
        BitEnumField('R', None, 7, R_ENUM),
    ]

class VTI(Packet):
    name = 'VTI'
    fields_desc = [
        BitEnumField('Transient', None, 1, TRANSIENT),
        BitField('Value', None, 7),
    ]

class DIQ(Packet):
    name = 'QDS'
    fields_desc = [
        ByteEnumField('DPI', 0x00, DPI_ENUM),
        FlagsField('flags', 0x00, 8, DIQ_FLAGS),
    ]

    def do_dissect(self, s):
        self.DPI = s[0] & 0x03
        self.flags = s[0] & 0xf0
        return s[1:]

    def do_build(self):
        s = list(range(1))
        s[0] = int(self.DPI) | int(self.flags)
        return bytes(s)

class QOS(Packet): # Section 7.2.6.39
    name = 'QOS'
    fields_desc = [
        BitEnumField('SE', 0x00, 1, SEL_EXEC),
        BitField('QL', 0x00, 7),
    ]

class CP56Time(Packet):

    name = 'CP56Time'
    fields_desc = [
        LEShortField('MS', 0),
        BitField('IV', 0, 1),
        BitField('RES1', 0, 1),
        BitField('Min', 0, 6),
        BitField('SU', 0, 1),
        BitField('RES2', 0, 2),
        BitField('Hour', 0, 5),
        BitEnumField('DOW', 0, 3, DOW_ENUM),
        BitField('Day', 0, 5),
        BitField('RES3', 0, 4),
        BitField('Month', 0, 4),
        BitField('RES4', 0, 1),
        BitField('Year', 0, 7),
    ]

class SCO(Packet):
    name = 'SCO'
    fields_desc = [
        BitEnumField('SE', 0, 1, SEL_EXEC),
        BitEnumField('QU', 0, 6, QU_ENUM),
        BitEnumField('SCS', 0, 1, SCS_ENUM),
    ]

class IOA1(Packet):
    name = 'IOA'
    fields_desc = [
        IOAID('IOA', None),
        FlagsField('SIQ', 0x00, 8, SIQ_FLAGS),
    ]

class IOA3(Packet):
    name = 'IOA'
    fields_desc = [
        IOAID('IOA', None),
        PacketField('DIQ', None, DIQ)
    ]

class IOA5(Packet):
    name = 'IOA'
    fields_desc = [
        IOAID('IOA', None),
        PacketField('VTI', None, VTI),
        FlagsField('QDS', 0x00, 8, QDS_FLAGS),
    ]

class IOA7(Packet):
    name = 'IOA'
    fields_desc = [
        IOAID('IOA', None),
        XIntField('BSI', 0x00000000),
        FlagsField('QDS', 0x00, 8, QDS_FLAGS),
    ]

class IOA9(Packet):
    name = 'IOA'
    fields_desc = [
        IOAID('IOA', None),
        SignedShortField('Value', None),
        FlagsField('QDS', 0x00, 8, QDS_FLAGS),
    ]

class IOA13(Packet):
    name = 'IOA'
    fields_desc = [
        IOAID('IOA', None),
        LEFloatField('Value', None),
        FlagsField('QDS', 0x00, 8, QDS_FLAGS),
    ]

class IOA30(Packet):
    name = 'IOA'
    fields_desc = [
        IOAID('IOA', None),
        FlagsField('SIQ', 0x00, 8, SIQ_FLAGS),
        PacketField('CP56Time', None, CP56Time)
    ]

class IOA31(Packet):
    name = 'IOA'
    fields_desc = [
        IOAID('IOA', None),
        PacketField('DIQ', None, DIQ),
        PacketField('CP56Time', None, CP56Time)
    ]

class IOA36(Packet):
    name = 'IOA'
    fields_desc = [
        IOAID('IOA', None),
        LEFloatField('Value', None),
        FlagsField('QDS', 0x00, 8, QDS_FLAGS),
        PacketField('CP56Time', None, CP56Time),
    ]

class IOA37(Packet):
    name = 'IOA'
    fields_desc = [
        IOAID('IOA', None),
        LEIntField('Binary_Counter', None),
        ByteField('SQ', 0),
        # BitField('CY', 0x00, 1),
        # BitField('CA', 0x00, 1),
        # BitField('IV', 0x00, 1),
        PacketField('CP56Time', None, CP56Time),
    ]

    # def do_dissect(self, s):
    #     # self.IOA = unpack('BBB',s[0],s[1],s[2]) 
    #     # self.Binary_Counter = s[3:7]
    #     # self.SQ = s[7] & 0x1F
    #     # self.CY = s[7] & 0x20
    #     # self.CA = s[7] & 0x40
    #     # self.IV = s[7] & 0x80
    #     # self.CP56Time = s[8:]

    # def do_build(self):
    #     s = bytearray()
    #     s.append(self.IOA)
    #     s.append(self.Binary_Counter)
    #     s.append(self.SQ|self.CY|self.CA|self.IV)
    #     s.append(self.CP56Time)

class IOA45(Packet):
    name = 'IOA'
    fields_desc = [
        IOAID('IOA', None),
        PacketField('SCO', None, SCO)
    ]

class IOA50(Packet):
    name = 'IOA'
    fields_desc = [
        IOAID('IOA', None),
        LEFloatField('Value', None),
        PacketField('QOS', None, QOS)
    ]

class IOA70(Packet):
    name = 'IOA'
    fields_desc = [
        IOAID('IOA', None),
        PacketField('COI', None, COI),
    ]

class IOA100(Packet):
    name = 'IOA'
    fields_desc = [
        IOAID('IOA', None),
        ByteEnumField('QOI', None, QOI_ENUM),
    ]

class IOA103(Packet):
    name = 'IOA'
    fields_desc = [
        IOAID('IOA', None),
        PacketField('CP56Time', None, CP56Time)
    ]

IOAS = {
    1: IOA1,
    3: IOA3,
    5: IOA5,
    7: IOA7,
    9: IOA9,
    13: IOA13,
    30: IOA30,
    31: IOA31,
    36: IOA36,
    37: IOA37,
    45: IOA45,
    50: IOA50,
    70: IOA70,
    100: IOA100,
    103: IOA103,
}

IOALEN = {
    1: 4,
    3: 4,
    5: 5,
    7: 8,
    9: 6,
    13: 8,
    30: 10,
    31: 11,
    36: 15,
    37: 25,
    45: 4,
    50: 8,
    70: 4,
    100: 4,
    103: 10,
}
