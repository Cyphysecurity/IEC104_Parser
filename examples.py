#!/usr/bin/env python3
from IEC104_Raw.dissector import APDU 
from binascii import unhexlify

print('')
print('ASDU TypeID M_ME_TF_1 (36)')
print('')
data36 = unhexlify('6819c45902002401030001001304007f1daf4200b922120a0b0811')
APDU(data36).show()


print('')
print('ASDU TypeID M_ME_NC_1 (13)')
print('')
data13 = unhexlify('6812aaf380150d0103000114eb030017ad304300')
APDU(data13).show()