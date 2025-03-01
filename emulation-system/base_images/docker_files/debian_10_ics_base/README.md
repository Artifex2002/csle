# PLC Emulation Docker Container

## Overview
This Docker container is designed to emulate a **Programmable Logic Controller (PLC)** environment by replicating key ICS/OT functionalities. The purpose of this emulation is to provide a platform for **attacker-defender reinforcement learning (RL) simulations** in cybersecurity, where agents can interact with and attack/defend a simulated PLC.

Since industrial PLCs do not expose conventional IT services, this container includes network services that approximate real PLC behavior. Additionally, diagnostic tools are included to facilitate **data collection** for RL training. These tools stand in for real-world PLC diagnostic features, such as Allen-Bradley's **CIP Get Attribute** commands or Siemens **S7 diagnostic reads**.

## Features and Rationales
Below is a breakdown of the components included in this Docker container, their roles, and how they correspond to real PLC functionalities.

| **Component**         | **Purpose in Docker**                                   | **Analogy in a Real PLC**                                       |
|-----------------------|--------------------------------------------------------|----------------------------------------------------------------|
| **Modbus Server** (`pymodbus`) | Provides a basic ICS protocol for communication | Many PLCs use Modbus/TCP for control and data exchange         |
| **OPC UA Server** (`python-opcua`) | Enables secure, structured industrial communication | Used in modern PLCs for vendor-neutral interoperability        |
| **EtherNet/IP Support** (Future addition) | Simulates Rockwell’s CIP-based PLC interaction | Common in Allen-Bradley PLCs                                   |
| **S7 Protocol Server** (`python-snap7`) | Simulates Siemens PLC communication | Used in Siemens PLCs for program updates and diagnostics      |
| **SSH** | Provides remote access to manage and inspect the container | Analogous to engineering tool access for PLC maintenance       |
| **sysstat** | Monitors CPU, memory, I/O for diagnostics | Real PLCs expose this via proprietary methods (e.g., CIP Attributes) |
| **Beats** (Filebeat, Metricbeat, Packetbeat) | Collects logs, metrics, and network traffic for RL training | In real PLCs, this data is accessed via SCADA or vendor tools |
| **csle-collector** | Aggregates security logs for analysis | Represents external SIEM/logging systems used in ICS security |
| **OpenSSL** | Provides cryptographic functions for secure OPC UA | Real PLCs implement TLS encryption, often using embedded libraries |
| **iptables** | Allows firewall rule simulations in ICS networks | Real PLCs use hardware-based firewalls or network segmentation |
| **NTP** | Synchronizes system time for accurate logging | Real PLCs rely on industrial NTP servers for event timestamping |

## Rationale for Each Inclusion
### 1. **ICS Protocols: Modbus, OPC UA, S7**
Real PLCs communicate using industry-standard protocols. These protocols allow:
- **Modbus**: Simple, register-based communication.
- **OPC UA**: Secure and structured communication, replacing legacy OPC DA.
- **S7**: Proprietary Siemens protocol for data exchange and configuration.
These inclusions allow attackers to test known exploits such as unauthorized register manipulation, protocol fuzzing, and unauthorized control commands.

### 2. **OpenPLC Integration**
This container includes **OpenPLC**, an open-source **Programmable Logic Controller (PLC) runtime** that supports **IEC 61131-3** programming languages such as:
- **Ladder Logic (LD)**
- **Structured Text (ST)**
- **Function Block Diagram (FBD)**
- **Instruction List (IL)**
- **Sequential Function Chart (SFC)**

**OpenPLC Features:**
- **Web-based IDE** (`http://localhost:8080`) for programming and deployment.
- **Modbus TCP & OPC UA Support** for industrial communication.
- **Cross-platform**—runs on multiple architectures, including Raspberry Pi, ARM, and x86.
- **Custom I/O Mapping** for flexible integration with ICS networks.

This allows the container to function as a fully programmable industrial controller, suitable for **cybersecurity research, digital twins, and industrial automation prototyping**.


### 3. **SSH for Remote Administration**
- While real PLCs do **not** typically offer SSH, we include it for practical **container management** and **training RL agents** to interact with remote systems.
- This can be seen as an analogy for **engineering workstation access** to configure or update a PLC.

### 4. **Sysstat and Beats for Diagnostic Data Collection**
- **sysstat** collects CPU, memory, and I/O usage, **mimicking PLC resource diagnostics** (e.g., Rockwell’s **CIP Get Attribute**, Siemens diagnostic data, which often expose status data—CPU load, memory usage, fault states, etc.).
- **Beats** ships system logs and performance data, **analogous to SCADA systems collecting data from PLCs**.
- **csle-collector** aggregates security-related logs to simulate **ICS SOC (Security Operations Center) monitoring**.

The main difference is mechanism—industrial PLCs do this via CIP or vendor protocols, while our Docker container can do it via typical Linux tooling.

### 5. **OpenSSL for Secure Communications**
- Real PLCs use TLS encryption in OPC UA and other secure protocols.
- OpenSSL provides the cryptographic backend for secure OPC UA implementation.
- It also allows for **certificate-based authentication**, which is used in industrial environments.

Many modern PLCs do support secure, certificate-based communications (for example, Secure OPC UA), they might embed a smaller or different TLS/crypto library (e.g., WolfSSL, mbedTLS, or a proprietary library).
The PLC firmware implements the security handshake behind the scenes.

### 6. **iptables for Firewall Emulation**
- Real ICS networks implement **firewalls and segmentation** to protect PLCs.
- Using `iptables`, we can simulate **host-based firewalling**, restricting access to specific services.

### 7. **NTP for Time Synchronization**
- Real PLCs rely on industrial **NTP servers** to keep accurate timestamps for event logs and alarms.
- Including NTP ensures that logged attacks and events **align correctly in time**.

## Comparisons to Excluded Components from the Original CSLE Base Debian 10 Dockerfile
The original CSLE framework contained services that **are not relevant to a PLC**. These were removed for realism:
- **Web Servers (Apache, Tomcat, GlassFish)** → Not used in PLC firmware.
- **Database Servers (PostgreSQL, SQLite)** → SCADA, not PLC, stores historical data.
- **TeamSpeak, IRC, Mail Servers (Postfix, Sendmail, InspIRCd)** → Unrelated to ICS.
- **Exploit Scripts for IT (Heartbleed, SQL Injection, Telnet, Samba, etc.)** → Not applicable to ICS.
- **User Management Scripts** → PLCs don’t have multiple interactive users like an IT server.

## Usage
### Running the Container
```sh
docker build -t plc-emulator .
docker run -it --rm --network host plc-emulator
```

## Conclusion
This Docker container provides a realistic **PLC emulation** with key ICS functionalities. While it does not fully replicate vendor-specific hardware, it enables security research, **RL-based attack/defense training**, and **ICS cybersecurity testing** in a controlled lab setting. Future enhancements will improve the realism and expand attack/defense capabilities for RL simulations.