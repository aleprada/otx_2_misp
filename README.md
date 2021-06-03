
**Work in progress. The script is not finished yet.**

**otx_2misp**  
This script allows you to gather Indicator of Compromise (IoCs) from your [OTX](https://otx.alienvault.com/) suscribed pulses and send them to MISP
for Threat Intelligence analysis. The script uses the [OTX Python SDK](https://github.com/AlienVault-OTX/OTX-Python-SDK) and [PyMISP](https://github.com/MISP/PyMISP) 
Python libraries.

The script needs the following configuration:
* config->**config.ini**: OTX configuration, MISP url and MISP API key.
* config->**keywords.txt**: The terms that you to want to monitor on your Pulses.
* config->**attack_ids.txt**: ATT&CK techniques for filtering Pulses related to these techniques. (e.g. T1078 that stands for ATT&CK Enterprise Valid accounts)


**How it works?**

To Be Defined


   
**Usage**

To Be Defined

Gathering IoCs from OTX.
```bash 
python otx2misp.py