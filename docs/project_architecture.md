# Project Architecture
See the architecture diagram:
```bash
docs/architecture_diagram.md
```

## Overview

- The system processes network packets in **high-performance environments** using a **multi-threaded architecture**.

- Packet capture, processing, and monitoring are separated to **maximize throughput** and **reduce contention**.

- Real-time latency measurement is added for each packet.

The packet flow:

```bash
Network Interface
        │
        ▼
   Packet Capture
     (libpcap)
        │
        ▼
   Lock-Free Ring Buffer
        │
        ▼
  Worker Threads
 (Batch processing)
        │
        ▼
 Firewall Rules
        │
        ▼
 Packet Parsing
        │
        ▼
 Statistics / Monitoring
 (Packets/sec + Latency)
 ```

## System Components
Packet Capture

File:
```bash
src/packet_sniffer.c
```
* Captures packets from the network interface using ```libpcap```.

* Copies packets into internal buffers.

* Sends packets to the **lock-free ring buffer**.


## Packet Queue

File:
```bash
src/packet_queue.c
```
* Implements a **lock-free ring buffer** between capture and worker threads.

* Supports **batch dequeue** for high throughput.

* Ensures minimal locking overhead.

## Worker Threads

Workers are responsible for **processing packets in parallel**.

Each worker performs:

* Process packets in parallel using batch processing (BATCH_SIZE = 64).

* Steps per worker:

1. Dequeue batch

2. Validate Ethernet frame

3. Extract IP header

4. Apply firewall rules

5. Parse packet

6. Measure latency (microseconds)

## Firewall Rule Engine

File:
```bash
src/rules.c
```
* Blocks or allows packets based on IP rules.

* Example:
```bash
add_rule(&my_rules, inet_addr("8.8.8.8"), false);
```

## Packet Parser

File:
```bash
src/parser.c
```
The parser extracts protocol headers from raw packet data.

Supported protocols:

* Ethernet
* IPv4
* TCP
* UDP
* ICMP

Header structures are defined in:
```bash
include/packet.h
```

## Monitoring System

A dedicated monitoring thread prints statistics every second.

Displayed statistics:

* Packets processed per second
* Allowed packets
* Blocked packets
* Packet latency (avg/min/max)

Example output:
```bash
Packets processed: 720 pkt/s
Allowed packets: 510
Blocked packets: 210
```

## Benchmark Mode

The project includes two modes to compare performance.

### OLD System

Single-thread processing:
```bash
Capture → Parse → Filter
```

### NEW System

Multi-thread architecture:
```bash
Capture → ring buffer → Workers → Parse → Filter
```

Benchmark duration:
```bash
60 seconds
```

Results show **packets-per-second (PPS)** for both systems.

## File Map
```bash
src/
 packet_sniffer.c   -> main capture engine & latency measurement
 parser.c           -> advanced parser integrated with queue + workers
 packet_queue.c     -> lock-free ring buffer
 rules.c            -> firewall rules
 packet_parser.c      -> standalone raw socket TCP/IP packet sniffer
include/
 packet.h
 packet_queue.h
 rules.h
```