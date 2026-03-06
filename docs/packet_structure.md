# Packet Structure Overview
```c
Ethernet Frame
  ├─ Destination MAC
  ├─ Source MAC
  ├─ EtherType
  └─ Payload (IP Packet)
       ├─ Version / IHL / Protocol
       ├─ Source IP
       ├─ Destination IP
       └─ TCP / UDP
            ├─ Source Port
            ├─ Destination Port
            └─ Data
```