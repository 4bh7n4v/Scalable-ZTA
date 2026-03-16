from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel
import time

# --- TOPOLOGY ---
class ZTTopology(Topo):
    def build(self):
        # Hosts
        Initiating  = self.addHost('Initiating',  ip='10.0.0.1/24')
        FEP         = self.addHost('FrontProxy',  ip='10.0.0.10/24')
        PDP         = self.addHost('Controller',  ip='10.0.2.1/24')
        PEP         = self.addHost('SDPGateway')                      # multi-homed, set manually
        Resource    = self.addHost('Resource',    ip='10.0.1.5/24')

        # Switches
        s1 = self.addSwitch('s1')   # Ingress
        s2 = self.addSwitch('s2')   # Management / mTLS
        s3 = self.addSwitch('s3')   # Data Plane / WireGuard
        s4 = self.addSwitch('s4')   # Egress / Resource

        # --- S1 Links (Ingress) ---
        # Port order matters — must match Ryu constants
        # s1-port1 = Initiating, s1-port2 = FrontProxy, s1-port3 = s3
        self.addLink(Initiating, s1)   # Initiating-eth0  <-> s1-port1
        self.addLink(FEP, s1)          # FrontProxy-eth0  <-> s1-port2
        self.addLink(s1, s3)           # s1-port3         <-> s3-port1

        # --- S2 Links (Management / mTLS) ---
        # s2-port1 = Controller, s2-port2 = SDPGateway
        self.addLink(PDP, s2)          # Controller-eth0  <-> s2-port1
        self.addLink(PEP, s2)          # SDPGateway-eth0  <-> s2-port2

        # --- S3 Links (Data Plane) ---
        # s3-port1 = s1 (already added above), s3-port2 = SDPGateway
        self.addLink(s3, PEP)          # s3-port2         <-> SDPGateway-eth1

        # --- S4 Links (Resource) ---
        # s4-port1 = SDPGateway, s4-port2 = Resource
        self.addLink(PEP, s4)          # SDPGateway-eth2  <-> s4-port1
        self.addLink(s4, Resource)     # s4-port2         <-> Resource-eth0

        # --- Direct Management Link (out of band, no switch) ---
        self.addLink(FEP, PDP)         # FrontProxy-eth1  <-> Controller-eth1


# --- CUSTOM CLI ---
class CustomCLI(CLI):

    def do_ports(self, line):
        """Print actual port assignments for all switches."""
        net = self.mn
        for sw_name in ['s1', 's2', 's3', 's4']:
            sw = net.get(sw_name)
            print(f"\n[{sw_name}]")
            for intf in sw.intfList():
                if intf.name != 'lo':
                    print(f"  port {sw.ports[intf]:2d} = {intf.name}")

    def do_Connect_Openssl(self, line):
        """Generate SAN certs and test bidirectional mTLS."""
        net = self.mn
        PDP = net.get('Controller')
        PEP = net.get('SDPGateway')

        print("\n*** Phase 1: Creating Workspaces")
        for node in [PDP, PEP]:
            node.cmd(f'rm -rf /tmp/{node.name}_workspace && mkdir -p /tmp/{node.name}_workspace')
        PDP.cmd('rm -rf /tmp/CA_workspace && mkdir -p /tmp/CA_workspace')

        print("*** Phase 2: Generating CA")
        PDP.cmd('openssl genrsa -out /tmp/CA_workspace/ca.key 2048')
        PDP.cmd('openssl req -x509 -new -nodes -key /tmp/CA_workspace/ca.key '
                '-sha256 -days 1024 -out /tmp/CA_workspace/ca.crt '
                '-subj "/CN=ZeroTrustCA"')

        print("*** Phase 3: Creating SAN Config Files")
        PDP.cmd("""cat <<EOF > /tmp/Controller_workspace/PDP.cnf
[req]
distinguished_name = dn
req_extensions = ext
prompt = no
[dn]
CN = controller.zt
[ext]
subjectAltName = IP:10.0.2.1
extendedKeyUsage = serverAuth, clientAuth
keyUsage = critical, digitalSignature, keyEncipherment
EOF""")

        PEP.cmd("""cat <<EOF > /tmp/SDPGateway_workspace/PEP.cnf
[req]
distinguished_name = dn
req_extensions = ext
prompt = no
[dn]
CN = gateway.zt
[ext]
subjectAltName = IP:10.0.2.254
extendedKeyUsage = serverAuth, clientAuth
keyUsage = critical, digitalSignature, keyEncipherment
EOF""")

        print("*** Phase 4: Keys, CSRs, and SAN Signing")
        # Controller cert
        PDP.cmd('openssl genrsa -out /tmp/Controller_workspace/PDP.key 2048')
        PDP.cmd('openssl req -new -key /tmp/Controller_workspace/PDP.key '
                '-out /tmp/Controller_workspace/PDP.csr '
                '-config /tmp/Controller_workspace/PDP.cnf')
        PDP.cmd('openssl x509 -req -in /tmp/Controller_workspace/PDP.csr '
                '-CA /tmp/CA_workspace/ca.crt -CAkey /tmp/CA_workspace/ca.key '
                '-CAcreateserial -out /tmp/Controller_workspace/PDP.crt '
                '-days 365 -extensions ext -extfile /tmp/Controller_workspace/PDP.cnf')

        # Gateway cert — CSR generated on PEP, signed by CA on PDP
        PEP.cmd('openssl genrsa -out /tmp/SDPGateway_workspace/PEP.key 2048')
        PEP.cmd('openssl req -new -key /tmp/SDPGateway_workspace/PEP.key '
                '-out /tmp/SDPGateway_workspace/PEP.csr '
                '-config /tmp/SDPGateway_workspace/PEP.cnf')
        PDP.cmd('cp /tmp/SDPGateway_workspace/PEP.csr /tmp/Controller_workspace/PEP.csr')
        PDP.cmd('cp /tmp/SDPGateway_workspace/PEP.cnf /tmp/Controller_workspace/PEP.cnf')
        PDP.cmd('openssl x509 -req -in /tmp/Controller_workspace/PEP.csr '
                '-CA /tmp/CA_workspace/ca.crt -CAkey /tmp/CA_workspace/ca.key '
                '-CAcreateserial -out /tmp/Controller_workspace/PEP.crt '
                '-days 365 -extensions ext -extfile /tmp/Controller_workspace/PEP.cnf')
        PDP.cmd('cp /tmp/Controller_workspace/PEP.crt /tmp/SDPGateway_workspace/PEP.crt')

        # Distribute CA cert
        PDP.cmd('cp /tmp/CA_workspace/ca.crt /tmp/Controller_workspace/ca.crt')
        PDP.cmd('cp /tmp/CA_workspace/ca.crt /tmp/SDPGateway_workspace/ca.crt')

        print("*** Phase 5: Direction A  (Controller → SDPGateway:4433)")
        PEP.cmd('pkill -f "openssl s_server"')
        PEP.cmd('openssl s_server '
                '-accept 10.0.2.254:4433 '
                '-cert /tmp/SDPGateway_workspace/PEP.crt '
                '-key  /tmp/SDPGateway_workspace/PEP.key '
                '-CAfile /tmp/SDPGateway_workspace/ca.crt '
                '-Verify 1 -www -quiet &')
        time.sleep(2)
        result_a = PDP.cmd('echo "Q" | openssl s_client '
                           '-connect 10.0.2.254:4433 '
                           '-cert /tmp/Controller_workspace/PDP.crt '
                           '-key  /tmp/Controller_workspace/PDP.key '
                           '-CAfile /tmp/Controller_workspace/ca.crt '
                           '-brief 2>&1')
        if 'Verification: OK' in result_a:
            print('[SUCCESS] Direction A mTLS OK ✅')
        else:
            print(f'[FAIL] Direction A ❌\n{result_a}')

        print("*** Phase 6: Direction B  (SDPGateway → Controller:4434)")
        PEP.cmd('pkill -f "openssl s_server"')
        PDP.cmd('pkill -f "openssl s_server"')
        PDP.cmd('openssl s_server '
                '-accept 10.0.2.1:4434 '
                '-cert /tmp/Controller_workspace/PDP.crt '
                '-key  /tmp/Controller_workspace/PDP.key '
                '-CAfile /tmp/Controller_workspace/ca.crt '
                '-Verify 1 -www -quiet &')
        time.sleep(2)
        result_b = PEP.cmd('echo "Q" | openssl s_client '
                           '-connect 10.0.2.1:4434 '
                           '-cert /tmp/SDPGateway_workspace/PEP.crt '
                           '-key  /tmp/SDPGateway_workspace/PEP.key '
                           '-CAfile /tmp/SDPGateway_workspace/ca.crt '
                           '-brief 2>&1')
        if 'Verification: OK' in result_b:
            print('[SUCCESS] Direction B mTLS OK ✅')
        else:
            print(f'[FAIL] Direction B ❌\n{result_b}')


# --- EXECUTION ---
def run():
    topo = ZTTopology()
    net = Mininet(
        topo=topo,
        controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6633),
        autoSetMacs=True
    )

    print("[*] Starting Network")
    net.start()

    # Allow Ryu time to connect and push flows before any pings
    print("[*] Waiting for Ryu to install flows...")
    time.sleep(3)

    PEP    = net.get('SDPGateway')
    PDP    = net.get('Controller')
    FEP    = net.get('FrontProxy')
    Client = net.get('Initiating')
    Server = net.get('Resource')

    print("[*] Configuring Interfaces...")

    # ── Out-of-band management link (FEP <-> PDP direct, no switch) ──
    FEP.cmd('ip link set FrontProxy-eth1 up')
    FEP.cmd('ip addr flush dev FrontProxy-eth1')
    FEP.cmd('ip addr add 10.0.3.10/24 dev FrontProxy-eth1')

    PDP.cmd('ip link set Controller-eth1 up')
    PDP.cmd('ip addr flush dev Controller-eth1')
    PDP.cmd('ip addr add 10.0.3.100/24 dev Controller-eth1')

    # ── S2 control plane (mTLS) ──
    PDP.cmd('ip link set Controller-eth0 up')
    PDP.cmd('ip addr flush dev Controller-eth0')
    PDP.cmd('ip addr add 10.0.2.1/24 dev Controller-eth0')

    PEP.cmd('ip link set SDPGateway-eth0 up')
    PEP.cmd('ip addr flush dev SDPGateway-eth0')
    PEP.cmd('ip addr add 10.0.2.254/24 dev SDPGateway-eth0')

    # ── S1 ingress plane ──
    FEP.cmd('ip link set FrontProxy-eth0 up')
    FEP.cmd('ip addr flush dev FrontProxy-eth0')
    FEP.cmd('ip addr add 10.0.0.10/24 dev FrontProxy-eth0')

    Client.cmd('ip link set Initiating-eth0 up')
    Client.cmd('ip addr flush dev Initiating-eth0')
    Client.cmd('ip addr add 10.0.0.1/24 dev Initiating-eth0')

    # ── S3/S4 data plane ──
    PEP.cmd('ip link set SDPGateway-eth1 up')
    PEP.cmd('ip addr flush dev SDPGateway-eth1')
    PEP.cmd('ip addr add 10.0.0.254/24 dev SDPGateway-eth1')

    PEP.cmd('ip link set SDPGateway-eth2 up')
    PEP.cmd('ip addr flush dev SDPGateway-eth2')
    PEP.cmd('ip addr add 10.0.1.254/24 dev SDPGateway-eth2')

    Server.cmd('ip link set Resource-eth0 up')
    Server.cmd('ip addr flush dev Resource-eth0')
    Server.cmd('ip addr add 10.0.1.5/24 dev Resource-eth0')

    # ── IP forwarding on gateway ──
    PEP.cmd('sysctl -w net.ipv4.ip_forward=1')

    # ── Routing ──
    # Client reaches resource subnet via gateway
    # Client.cmd('ip route add 10.0.1.0/24 via 10.0.0.254 dev Initiating-eth0')

    # Resource returns traffic via gateway
    Server.cmd('ip route add default via 10.0.1.254 dev Resource-eth0')

    # Gateway knows both subnets via its own interfaces (implicit),
    # but needs explicit routes if kernel doesn't auto-add them
    PEP.cmd('ip route add 10.0.0.0/24 dev SDPGateway-eth1')
    PEP.cmd('ip route add 10.0.1.0/24 dev SDPGateway-eth2')

    # Controller reaches gateway via S2
    PDP.cmd('ip route add 10.0.2.0/24 dev Controller-eth0')

    # ── Static ARP hardening on S2 plane ──
    # Flush first, then set — avoids ghost entries from previous runs
    PDP.cmd('ip neigh flush dev Controller-eth0')
    PEP.cmd('ip neigh flush dev SDPGateway-eth0')

    pdp_mac = PDP.MAC(intf='Controller-eth0')
    pep_mac = PEP.MAC(intf='SDPGateway-eth0')
    PEP.cmd(f'arp -i SDPGateway-eth0 -s 10.0.2.1 {pdp_mac}')
    PDP.cmd(f'arp -i Controller-eth0 -s 10.0.2.254 {pep_mac}')

    # ── Connectivity checks ──
    print("\n[*] Connectivity Checks:")

    mgmt_ping = FEP.cmd('ping -I FrontProxy-eth1 -c 1 -W 2 10.0.3.100')
    ctrl_ping = PDP.cmd('ping -I Controller-eth0 -c 1 -W 2 10.0.2.254')

    print(f"  Management link  (FEP  → PDP  direct): "
          f"{'OK ✅' if '0% packet loss' in mgmt_ping else 'FAILED ❌'}")
    print(f"  Control plane    (PDP  → PEP  via S2): "
          f"{'OK ✅' if '0% packet loss' in ctrl_ping else 'FAILED ❌'}")

    CustomCLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run()