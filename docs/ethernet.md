# Ethernet Frame Structure

- Destination MAC (6 bytes)
- Source MAC (6 bytes)
- EtherType (2 bytes)
- Payload (46–1500 bytes)

Example:
```c
Ethernet
  └─ IP
       └─ TCP
            └─ Data
```