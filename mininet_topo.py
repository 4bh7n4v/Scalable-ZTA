from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel
import time

# --- TOPOLOGY DEFINITION ---

class ZTTopology(Topo):
    def build(self):
        # Hosts
        client = self.addHost('Intiating', ip='10.0.0.1')
        pdp = self.addHost('PDP', ip='10.0.0.2')
        pep = self.addHost('PEP', ip='10.0.0.3')
        resource = self.addHost('Resource', ip='10.0.0.4')
        ca_node = self.addHost('CA', ip='10.0.0.5')
        

        # Switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')

        # Links [cite: 1, 3]
        self.addLink(ca_node, s1)
        self.addLink(client, s1)
        self.addLink(pdp, s1)
        self.addLink(s1, s2)
        self.addLink(s2, pep)
        self.addLink(s2, resource)

# --- CUSTOM CLI COMMANDS ---

class CustomCLI(CLI):
    def do_Connect_Openssl(self, line):
        """Automates proper mTLS setup between PDP, PEP, and CA with SAN + EKU."""
        net = self.mn
        pdp = net.get('PDP')
        pep = net.get('PEP')
        ca  = net.get('CA')

        print("*** Creating workspaces in /tmp...")
        for node in [pdp, pep, ca]:
            node.cmd(f'mkdir -p /tmp/{node.name}_workspace')

        # --- PHASE 1: CA Setup ---
        print("*** Phase 1: Initializing CA")
        ca.cmd('cd /tmp/CA_workspace && openssl genrsa -out ca.key 2048')
        ca.cmd('cd /tmp/CA_workspace && openssl req -x509 -new -nodes -key ca.key -sha256 -days 1024 -out ca.crt -subj "/CN=MyTestCA"')

        # --- PHASE 2: Create OpenSSL config with SAN + EKU ---
        print("*** Phase 2: Creating SAN + EKU configs")

        pdp_cnf = """
        [ req ]
        prompt = no
        default_bits = 2048
        default_md = sha256
        distinguished_name = dn
        req_extensions = req_ext

        [ dn ]
        CN = controller.local

        [ req_ext ]
        keyUsage = critical, digitalSignature, keyEncipherment
        extendedKeyUsage = serverAuth, clientAuth
        subjectAltName = @alt_names

        [ alt_names ]
        IP.1 = 10.0.0.2
        DNS.1 = controller.local
        """

        pep_cnf = """
        [ req ]
        prompt = no
        default_bits = 2048
        default_md = sha256
        distinguished_name = dn
        req_extensions = req_ext

        [ dn ]
        CN = gateway.local

        [ req_ext ]
        keyUsage = critical, digitalSignature, keyEncipherment
        extendedKeyUsage = serverAuth,clientAuth
        subjectAltName = @alt_names

        [ alt_names ]
        IP.1 = 10.0.0.3
        DNS.1 = gateway.local
        """

        pdp.cmd(f'echo "{pdp_cnf}" > /tmp/PDP_workspace/pdp.cnf')
        pep.cmd(f'echo "{pep_cnf}" > /tmp/PEP_workspace/pep.cnf')

        # --- PHASE 3: Generate Keys + CSRs ---
        print("*** Phase 3: Generating keys + CSRs")
        pdp.cmd('cd /tmp/PDP_workspace && openssl genrsa -out pdp.key 2048')
        pdp.cmd('cd /tmp/PDP_workspace && openssl req -new -key pdp.key -out pdp.csr -config pdp.cnf')

        pep.cmd('cd /tmp/PEP_workspace && openssl genrsa -out pep.key 2048')
        pep.cmd('cd /tmp/PEP_workspace && openssl req -new -key pep.key -out pep.csr -config pep.cnf')

        # --- PHASE 4: CA Signs Certificates ---
        print("*** Phase 4: CA signing certs")
        ca.cmd('openssl x509 -req -in /tmp/PDP_workspace/pdp.csr '
            '-CA /tmp/CA_workspace/ca.crt -CAkey /tmp/CA_workspace/ca.key '
            '-CAcreateserial -out /tmp/PDP_workspace/pdp.crt -days 365 -sha256 '
            '-extfile /tmp/PDP_workspace/pdp.cnf -extensions req_ext')

        ca.cmd('openssl x509 -req -in /tmp/PEP_workspace/pep.csr '
            '-CA /tmp/CA_workspace/ca.crt -CAkey /tmp/CA_workspace/ca.key '
            '-CAcreateserial -out /tmp/PEP_workspace/pep.crt -days 365 -sha256 '
            '-extfile /tmp/PEP_workspace/pep.cnf -extensions req_ext')

        # --- PHASE 5: Start PDP mTLS Server ---
        print("*** Phase 5: Starting PDP mTLS server")
        pdp.cmd('openssl s_server -accept 4433 '
                '-cert /tmp/PDP_workspace/pdp.crt '
                '-key /tmp/PDP_workspace/pdp.key '
                '-CAfile /tmp/CA_workspace/ca.crt -Verify 1 &')

        import time
        time.sleep(1)

        # --- PHASE 6: PEP connects to PDP ---
        print("*** Phase 6: PEP connecting to PDP via mTLS")
        result = pep.cmd('openssl s_client -connect 10.0.0.2:4433 '
                        '-cert /tmp/PEP_workspace/pep.crt '
                        '-key /tmp/PEP_workspace/pep.key '
                        '-CAfile /tmp/CA_workspace/ca.crt < /dev/null')

        if "Verify return code: 0 (ok)" in result:
            print("\n[SUCCESS] mTLS established between PEP and PDP ✔")
        else:
            print("\n[ERROR] mTLS failed ❌")
            print(result)


# --- NETWORK EXECUTION ---


def run():
    topo = ZTTopology()

    net = Mininet(
        topo=topo,
        controller=lambda name: RemoteController(name, ip='172.20.10.12', port=6633),
        ipBase='10.0.0.0/24',
        autoSetMacs=True
    )

    print("[*] Starting Network")
    net.start()

    # Get hosts
    client = net.get('Intiating')
    pdp = net.get('PDP')
    pep = net.get('PEP')

    # Add default route only for PDP (so it can reach Ubuntu host)
    pdp.cmd('ip route add default via 10.0.0.254')

    print("[*] Network Ready. Custom CLI starting...")
    CustomCLI(net)

    print("[*] Stopping Network")
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()