# ZeroTrust_MininetSetup
### Zero Trust Network Architecture Emulation in Mininet — Scalable Working Project

> Zero Trust Architecture Emulation using Mininet & Ryu SDN Controller

---

## Phase 1 — Mininet Emulation

This project demonstrates a Zero Trust Network Architecture (ZTNA) emulation using Mininet and the Ryu SDN Controller. It models a 4-node topology with a gateway enforcing access control using SDN principles.

**Simulates:**
- Controller-driven authentication & policy enforcement
- Gateway-based access mediation
- Secure, segmented communication paths

### Components

| Node | Role |
|---|---|
| Client Node | Initiates access requests |
| Gateway Node | Single IP acts as enforcement point |
| Resource/Server Node | Protected backend |
| Policy/Controller Node | SDN policy engine |

**Network:**
- 2 OpenFlow switches
- Switches interconnected
- Gateway connected to both segments

---

## Phase 2 — Working ZTNA System

### Components

| Component | Description |
|---|---|
| `spa_server.py` | Receives, decrypts, and validates SPA knock packets |
| `spa_client.py` | Sends encrypted SPA and exchanges WireGuard keys |
| `Gateway_SSL.py` | Manages WireGuard peers and firewall rules over TLS |
| `add_wg_peer.py` | Provisions WireGuard peers on the gateway |
| `IP_Address_Manager.py` | SQLite IPAM — lease allocation, renewal, revocation |
| `Client_History.json` | Audit log — access events with status and timestamps |
| `sdp_gateway_details.json` | Gateway registry — subnet, VPN IPs, SSH details |

### New Capabilities over Phase 1

- Single Packet Authorization (SPA) — port stays closed until valid knock
- AES-CBC + HMAC-SHA256 encrypted SPA packets
- WireGuard VPN tunnels — dynamically provisioned per client
- SQLite IPAM — VPN IP lease allocation with expiry and renewal
- Multi-client support — concurrent sessions tracked independently
- Lease monitor — auto-revokes expired sessions
- Peer cleanup thread — removes timed-out WireGuard peers
- SDN integration — signals Ryu via FrontProxy to open/close switch flows
- Audit logging — every access event stored with status lifecycle

---

## Screenshots

> Add your images inside an `images/` folder in the repo root and update the paths below.

**Phase 1 — Mininet Topology**

![Phase 1 Topology](images/phase1_topology.png)

**Phase 2 — System in Action**

![Phase 2 Running](images/phase2_running.png)

---

## Setup

### Requirements

```bash
pip install -r requirements.txt
```

### Run

```bash
# Start SPA server
sudo python3 spa_server.py

# Verbose output
sudo python3 spa_server.py -v

# Custom port
sudo python3 spa_server.py -p 12345

# Daemon mode
sudo python3 spa_server.py --daemon
```

### Fix Stuck WireGuard Interface

```bash
sudo ip link delete wg0
sudo chmod 600 /tmp/CA_workspace/wg0.conf
sudo wg-quick up /tmp/CA_workspace/wg0.conf
```

---

*Zero Trust: Never trust. Always verify. Limit access. Revoke fast.*

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

