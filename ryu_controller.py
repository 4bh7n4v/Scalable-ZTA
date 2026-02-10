from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4
import requests
import time

# ----------------- CONFIG ----------------- #

AUTH_API_URL = "http://127.0.0.1:5000/auth"   # Flask policy API

CLIENT_IP     = "10.0.0.1"   # h1
CONTROLLER_IP = "10.0.0.2"   # h2 (host, NOT Ryu)
GATEWAY_IP    = "10.0.0.3"   # h3
RESOURCE_IP   = "10.0.0.130"
CA_IP         = "10.0.0.5"


class ZTController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ZTController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}        # {dpid: {mac: port}}
        self.authenticated = False   # client auth state
        self.last_auth_check = 0     # rate limit API calls (seconds)
        self.auth_check_interval = 2 # seconds

    # ------------- UTILS ------------- #

    def _update_auth_state(self):
        """Poll Flask policy API with rate limiting."""
        now = time.time()
        if now - self.last_auth_check < self.auth_check_interval:
            return

        try:
            resp = requests.get(AUTH_API_URL, timeout=0.5).json()
            self.authenticated = resp.get("authenticated", False) # if authenticated is not found return False
        except Exception as e:
            self.logger.error(f"Auth API error: {e}")
            self.authenticated = False

        self.last_auth_check = now

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        """Install a flow rule."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout
        )
        datapath.send_msg(mod)

    def add_drop_flow(self, datapath, priority, match, idle_timeout=30):
        """Explicit drop flow (for denied traffic)."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = []  # no actions -> drop
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout
        )
        datapath.send_msg(mod)

    def is_always_allowed_pair(self, src_ip, dst_ip):
        """Flows that are allowed even before authentication."""
        pair = {src_ip, dst_ip}
        
        # 1. Client <-> Controller (For SPA/Auth packets)
        if pair == {CLIENT_IP, CONTROLLER_IP}:
            return True 
        # 2. Controller <-> Gateway (For policy updates)
        if pair == {CONTROLLER_IP, GATEWAY_IP}:
            return True
        # 3. Controller <-> CA (For certificate signing/validation)
        if pair == {CONTROLLER_IP, CA_IP}:
            return True
        # 4. CA <-> Gateway (For CRL/Revocation checks)
        if pair == {CA_IP, GATEWAY_IP}:
            return True
        return False

    def is_auth_based_allowed_pair(self, src_ip, dst_ip):
        """Flows that require the client to be authenticated."""
        pair = {src_ip, dst_ip}
        # 1. Allow Controller to manage Gateway

        if pair == {CLIENT_IP, GATEWAY_IP}:
            return True

        if pair == {GATEWAY_IP, RESOURCE_IP}:
            return True
        
        return False

    def is_flow_allowed(self, src_ip, dst_ip):
        """
        Decide if a flow between src_ip and dst_ip is allowed according to
        your Zero Trust workflow.
        """
        # 1) Always allow client <-> controller-host
        if self.is_always_allowed_pair(src_ip, dst_ip):
            return True

        # 2) For other flows, check authentication
        self._update_auth_state()

        if not self.authenticated:
            # Not authenticated -> everything else blocked
            return False

        # 3) Authenticated flows allowed
        return self.is_auth_based_allowed_pair(src_ip, dst_ip)

    # ------------- SWITCH SETUP ------------- #

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Install a table-miss entry that sends unmatched packets to controller.
        We enforce Zero Trust in packet_in_handler by selectively adding flows.
        """
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Table-miss: send to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info(f"Installed table-miss on switch {datapath.id}")

    # ------------- PACKET IN HANDLER ------------- #

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        in_port = msg.match['in_port']
        dpid = datapath.id

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # Ignore LLDP (used by some controllers)
        if eth.ethertype == 0x88cc:
            return

        src_mac = eth.src
        dst_mac = eth.dst

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port

        # Extract IP-layer info if present
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        arp_pkt = pkt.get_protocol(arp.arp)

        src_ip = None
        dst_ip = None

        if ipv4_pkt:
            src_ip = ipv4_pkt.src
            dst_ip = ipv4_pkt.dst
        elif arp_pkt:
            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip

        # If we don't know IPs (e.g., non-ARP non-IP packets), drop them.
        if not src_ip or not dst_ip:
            return

        # Decide if this IP pair is allowed under Zero Trust policy
        if not self.is_flow_allowed(src_ip, dst_ip):
            # Install a short-lived drop flow to avoid repeated packet_in
            match = parser.OFPMatch(
                eth_type=eth.ethertype,
                eth_src=src_mac,
                eth_dst=dst_mac
            )
            self.add_drop_flow(datapath, priority=20, match=match)
            self.logger.info(f"DENY {src_ip} -> {dst_ip} on switch {dpid}")
            return

        # Flow is allowed: determine output port
        out_port = None
        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            # For initial ARP/first packet, we may flood to discover the path.
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Install a unidirectional flow for this allowed communication
        match_fields = {
            'eth_type': eth.ethertype,
            'eth_src': src_mac,
            'eth_dst': dst_mac
        }

        # Try to match on IPs for IPv4/ARP for better specificity
        if ipv4_pkt:
            match_fields['ip_proto'] = ipv4_pkt.proto
            match_fields['ipv4_src'] = src_ip
            match_fields['ipv4_dst'] = dst_ip
        elif arp_pkt:
            match_fields['arp_spa'] = src_ip
            match_fields['arp_tpa'] = dst_ip

        match = parser.OFPMatch(**match_fields)
        self.add_flow(datapath, priority=50, match=match, actions=actions, idle_timeout=60)

        self.logger.info(f"ALLOW {src_ip} -> {dst_ip} via port {out_port} on switch {dpid}")

        # Send the current packet out
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data
        )
        datapath.send_msg(out)