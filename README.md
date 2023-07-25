# WEP-key-break

## Overview
This project was completed as part of the third-year data security course. The main objective of the project was to develop a tool for recovering a 5-byte WEP key using the 4RC stream cipher. WEP (Wired Equivalent Privacy) is an outdated wireless security protocol with known vulnerabilities, and this project aimed to exploit those weaknesses to recover the WEP key.

## Getting Started:
To use this WEP key recovery tool, follow these steps:

- Clone the repository: git clone https://github.com/michaelilkanayev1997/WEP-key-break.git
- Compile the source code : gcc break.c -lpcap -lssl -lcrypto -o break
- Run the tool: ./break
## Requirements:
This tool requires the pcap library to handle the packet capturing and parsing.
## Limitations:
The project was limited to educational and research purposes only and should not be used for any malicious activities.
The tool's effectiveness might vary depending on the complexity and level of encryption of the wireless traffic in the provided wep.pcap file.

## example:
<img src="https://github.com/michaelilkanayev1997/WEP-key-break/assets/93651794/38f1a10c-a370-4d9f-921d-59217c15f949" width="80%" height="80%"  ></img> 

