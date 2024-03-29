# Parser IEC104 Repo
This repository uses SCAPY as a tool for packet manipulation for SCADA traffic based on the standar IEC 60870-5-104. 

## Standard List
The parser was developed based on the following standars:
* IEC 60870-5-101: https://webstore.iec.ch/publication/3743&preview=1
* IEC 60870-5-104: https://webstore.iec.ch/publication/3746&preview=1

## Organization
* Library Folder
  * const.py: fixed values lists.
  * dissector.py: Dissector for Application Protocol Data Unit (APDU), Application Service Data Unit (ASDU), Application Protocol control Information (APCI).
  * fields.py: custom fields.
  * ioa.py: List of the differents ASDU type.
  
* Examples
  * ASDU Type M_ME_TF_1 (36): 6819c45902002401030001001304007f1daf4200b922120a0b0811
  * ASDU Type M_ME_NC_1 (13): 6812aaf380150d0103000114eb030017ad304300
  
## Getting started
1. Install the lastest version of Python: https://www.python.org/downloads/
2. Install SCAPY. To download the project: https://scapy.net/download/
3. Run the following test scrip:
```
from IEC104.dissector import APDU 
from binascii import unhexlify
  
data13 = unhexlify('6812aaf380150d0103000114eb030017ad304300')
APDU(data13).show()
``` 

## 
  
## Acknowledgements
This work was performed under the financial assistance award 70NANB17H282N from U.S. Department of Commerce, National Institute of Standards and Technology (NIST),  the National Science Foundation under award CNS-1929406, and by the Air Force Research Laboratory under agreement number FA8750-19-2-0010. The U.S. Government is authorized to reproduce and distribute reprints for Governmental purposes notwithstanding any copyright notation thereon.
  
