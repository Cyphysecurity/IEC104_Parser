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

TYPEID_ASDU = {
    0x24: 'M_ME_TF_1 (36)',
    0x0D: 'M_ME_NC_1 (13)',
    0x09: 'M_ME_NA_1 (9)',
    0x32: 'C_SE_NC_1 (50)',
    0x03: 'M_DP_NA_1 (3)',
    0x05: 'M_ST_NA_1 (5)',
    0x64: 'C_IC_NA_1 (100)',
    0x67: 'C_CS_NA_1 (103)',
    0x1E: 'M_SP_TB_1 (30)',
    0x46: 'M_EI_NA_1 (70)',
    0x1F: 'M_DP_TB_1 (31)',
    0x01: 'M_SP_NA_1 (1)',
    0x07: 'M_BO_NA_1 (7)',
}

TYPE_APCI = {
    0x00: 'I (0x00)',
    0x01: 'S (0x01)',
    0x03: 'U (0x03)'
}

UNNUMBERED_CONTROL_FIELD = {
    0x80: 'TESTFR con',
    0x40: 'TESTFR act',
    0x20: 'STOPDT con',
    0x10: 'STOPDT act',
    0x08: 'STARTDT con',
    0x04: 'STARTDT act'
}

CAUSE_OF_TX = {
    0: 'not used',
    1: 'per/cyc',
    2: 'back',
    3: 'spont',
    4: 'init',
    5: 'req',
    6: 'act',
    7: 'ActCon',
    8: 'deact',
    9: 'DeactCon',
    10: 'ActTerm',
    11: 'retrem',
    12: 'retloc',
    13: 'file',
    20: 'inrogen',
    21: 'inro1',
    22: 'inro2',
    23: 'inro3',
    24: 'inro4',
    25: 'inro5',
    26: 'inro6',
    27: 'inro7',
    28: 'inro8',
    29: 'inro9',
    30: 'inro10',
    31: 'inro11',
    32: 'inro12',
    33: 'inro13',
    34: 'inro14',
    35: 'inro15',
    36: 'inro16',
    37: 'reqcogen',
    38: 'reqco1',
    39: 'reqco2',
    40: 'reqco3',
    41: 'reqco4',
    44: 'unknown type identification',
    45: 'unknown cause of transmission',
    46: 'unknown common address of ASDU',
    47: 'unknown information object address'
}

SQ = {
    0X00: False,
    0x80: True
}

OV = {
    0X00: 'no overflow',
    0x01: 'overflow'
}

BL = {
    0X00: 'not blocked',
    0x10: 'blocked'
}

SB = {
    0X00: 'not substituted',
    0x20: 'substituted'
}

NT = {
    0X00: 'topical',
    0x40: 'not topical'
}

IV = {
    0X00: 'valid',
    0x80: 'invalid'
}

SU = {
    0X80: 'summer time',
    0x00: 'normal time'
}

#Day Of Week
DOW = {
    0x00: 'undefined',
    0x20: 'monday',
    0x40: 'tuesday',
    0x60: 'wednesday',
    0x80: 'thursday',
    0xA0: 'friday',
    0xC0: 'saturday',
    0xE0: 'sunday'
}

SE = {
    0x00: 'execute',
    0x80: 'select'
}

DPI = {
    0x00: 'indeterminate or intermediate state',
    0x01: 'determined state OFF',
    0x02: 'determined state ON',
    0x03: 'indeterminate state'
}

TRANSIENT = {
    0x00: 'not in transient',
    0x80: 'in transient'
}

QOi = {
    0x14: 'Station interrogation (global)',
    0x15: 'Interrogation of group 1',
    0x16: 'Interrogation of group 2',
    0x17: 'Interrogation of group 3',
    0x18: 'Interrogation of group 4',
    0x19: 'Interrogation of group 5',
    0x1A: 'Interrogation of group 6',
    0x1B: 'Interrogation of group 7',
    0x1C: 'Interrogation of group 8',
    0x1D: 'Interrogation of group 9',
    0x1E: 'Interrogation of group 10',
    0x1F: 'Interrogation of group 11',
    0x20: 'Interrogation of group 12',
    0x21: 'Interrogation of group 13',
    0x22: 'Interrogation of group 14',
    0x23: 'Interrogation of group 15',
    0x24: 'Interrogation of group 16'
}

SPI = {
    0x00: 'OFF',
    0x01: 'ON'
}

R = {
    0x00: 'local power switch on',
    0x01: 'local manual reset',
    0x02: 'remote reset',
}

I = {
    0x00: 'initialization with unchanged local parameters',
    0x80: 'initialization after change of local parameters'
}
