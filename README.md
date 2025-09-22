# MiniFirewall

A lightweight, C++-based packet monitoring and filtering firewall built with **libpcap**.  
MiniFirewall captures live network traffic, logs packets, and filters them according to user-defined rules.

---

## Features

- Real-time packet capture on any network interface.
- TCP, UDP, ICMP, and other protocols supported.
- Customizable firewall rules via a plain-text configuration file.
- Logs packet details with timestamp, IP addresses, ports, protocol, and length.
- Blocks unwanted traffic based on protocol, IP, or port.
- Modular design: firewall logic, packet parsing, and logging are separated.

---

## Folder Structure

|---src/


|-------main.cpp


|-------packet.cpp


|-------packet.hpp


|-------logger.cpp


|-------logger.hpp


|-------firewall.cpp


|-------firewall.hpp


|---build/


|---rules.conf


|---Makefile


|---CMakeLists.txt



## Installation

**Requirements:**

- macOS or Linux
- `libpcap` installed
- C++17 compiler
- CMake (optional)

**Build with CMake:**

```bash
cd path/to/MiniFirewall
mkdir build && cd build
cmake ..
make
```

## Usage

./minifw <interface> <rules_file>


./minifw en0 ../rules.conf


## Sample rules.conf

# Block traffic to a specific IP (e.g., GitHub)
BLOCK ANY ANY 140.82.113.21 0 0

# Block outgoing HTTP traffic
BLOCK TCP ANY ANY 0 80

# Block outgoing DNS traffic
BLOCK UDP ANY ANY 0 53

# Block all ping requests
BLOCK ICMP ANY ANY 0 0

# Allow all other traffic
ALLOW ANY ANY ANY 0 0


## Example Output

Listening on en0...
[2025-09-22 14:45:51] 192.168.0.113:60312 -> 140.82.113.21:443 TCP Length: 1490 bytes
[BLOCKED] Packet from 192.168.0.113 to 140.82.113.21


