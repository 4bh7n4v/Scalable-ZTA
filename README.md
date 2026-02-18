# ZeroTrust_MininetSetup
Zero Trust Network Architecture Emulation in Mininet For Scalabilty of the Working Project


# Zero Trust Architecture Emulation using Mininet & Ryu

This project demonstrates a **Zero Trust Network Architecture (ZTNA)** emulation using **Mininet** and the **Ryu SDN Controller**.  
It models a 4-node topology with a gateway enforcing access control using SDN principles.

The setup is designed to simulate:
- Controller-driven authentication & policy enforcement
- Gateway-based access mediation
- Secure, segmented communication paths

---

## 🧱 Topology Overview

**Components:**
- Client Node  
- Gateway Node (single IP, acts as enforcement point)  
- Resource/Server Node  
- Policy/Controller Node  

**Network:**
- 2 OpenFlow switches  
- Switches interconnected  
- Gateway connected to both segments  

---

## ⚙️ Environment

This project was developed inside a Python virtual environment.

| Component        | Version        |
|------------------|----------------|
| OS               | Ubuntu (VM)    |
| Python           | 3.8.20         |
| Mininet          | 2.3.0          |
| Ryu Controller   | 4.34           |
| Open vSwitch     | 3.6.1          |

---

## 📦 Python Dependencies

All dependencies are captured in:

