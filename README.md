# Parser IEC104 Repo
This repository uses SCAPY as a tool for packet manipulation. 
  
## Organization
The content of this repository includes:

* Library Folder
  * <text>
  
* Examples
  * ASDU Type M_ME_TF_1 (36): 6819c45902002401030001001304007f1daf4200b922120a0b0811
  * ASDU Type M_ME_NC_1 (13): 6812aaf380150d0103000114eb030017ad304300
  
## Getting started
1. Install the lastest version of Python: https://www.python.org/downloads/
2. Install SCAPY. To download the project: https://scapy.net/download/
3. <text>
```
from IEC104_Raw.dissector import APDU 
from binascii import unhexlify
  
data13 = unhexlify('6812aaf380150d0103000114eb030017ad304300')
APDU(data13).show()
``` 

4. 
  
  
## Acknowledgements
This work was performed under the financial assistance award 70NANB17H282N from U.S. Department of Commerce, National Institute of Standards and Technology (NIST),  the National Science Foundation under award CNS-1929406, and by the Air Force Research Laboratory under agreement number FA8750-19-2-0010. The U.S. Government is authorized to reproduce and distribute reprints for Governmental purposes notwithstanding any copyright notation thereon.
  
