# Simple Shell Scanner
PC network interface scanner for packages containing shellcode

## Description
Parses HTTP/TCP packets and checks the payload for shellcode in several primitive ways:
- Search for a sequence of NOP characters
- Signature search
- Search for byte matches with ranges of return addresses of popular shellcodes
- Decorating packages with Base64 and re-searching

## Requirements
- pcapplusplus
- npcap-sdk
- npcap

The libraries must be downloaded from official websites and placed in the appropriate folders: SimpleShellScanner/pcapplusplus and SimpleShellScanner/npcap-sdk

In addition, you need to install npcap on your PC

## Build
```
cd SimpleShellScanner
cmake -G "MinGW Makefiles" -S . -B build -DPcapPlusPlus_ROOT=SimpleShellScanner -DPCAP_ROOT=SimpleShellScanner/npcap-sdk -DPacket_ROOT=SimpleShellScanner/npcap-sdk
cmake --build build
```
