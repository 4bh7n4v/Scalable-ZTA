from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4
from ryu.lib.packet import tcp
from ryu.lib import hub
import requests
import collections

# ----------------- CONFIG ----------------- #

AUTH_API_URL = "http://10.0.0.2:5000/auth"

CLIENT_IP     = "10.0.0.1"   # h1
CONTROLLER_IP = "10.0.0.2"   # h2 (host, NOT Ryu)
GATEWAY_IP    = "10.0.0.3"   # h3
RESOURCE_IP   = "10.0.0.4"   # h4
CA_IP         = "10.0.0.5"
VM_ROOT_IP    = "10.0.0.100"

AUTH_POLL_INTERVAL    = 5     # seconds between auth API polls
AUTH_FAILURE_THRESHOLD = 3    # consecutive failures before revoking auth
MAC_TABLE_MAX         = 1024  # max MAC entries per switch before LRU eviction


class ZTController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ZTController, self).__init__(*args, **kwargs)

        self.mac_to_port = {}  # {dpid: OrderedDict(mac -> port)}

        # ---- Auth state ----
        # This is the only variable the packet handler ever reads.
        # It is updated exclusively by the background poller greenlet.
        # Because eventlet uses cooperative scheduling (not OS threads),
        # the poller and the packet handler never run at the same instant,
        # so a plain bool assignment is safe — no lock needed.
        self.authenticated = False
        self._fail_streak  = 0

        self._session = requests.Session()
        self._session.trust_env = False

        # Spawn the background poller once at startup.
        # From this point on, packet_in_handler just reads self.authenticated —
        # it never touches the network itself.
        hub.spawn(self._auth_poll_loop)

    # ------------------------------------------------------------------ #
    #  BACKGROUND AUTH POLLER                                             #
    #  Runs in its own greenlet, completely separate from packet handling. #
    #  Sleeps for AUTH_POLL_INTERVAL, wakes, hits the API, updates the    #
    #  boolean, goes back to sleep.  That's it.                           #
    # ------------------------------------------------------------------ #

    def _auth_poll_loop(self):
        while True:
            hub.sleep(AUTH_POLL_INTERVAL)   # yield; packet handler runs freely
            self._poll_once()

    def _poll_once(self):
        try:
            resp = self._session.get(AUTH_API_URL, timeout=(1, 4))
            resp.raise_for_status()
            new_state = resp.json().get("authenticated", False)

            # Only log when the state actually changes — reduces noise.
            if new_state != self.authenticated:
                self.logger.info(
                    "Auth state changed: %s -> %s",
                    self.authenticated, new_state
                )

            self.authenticated = new_state  # <-- single variable write
            self._fail_streak  = 0

        except Exception as e:
            self._fail_streak += 1
            self.logger.error("Auth poll failed (streak=%d): %s",
                              self._fail_streak, e)

            if self._fail_streak >= AUTH_FAILURE_THRESHOLD:
                if self.authenticated:          # only log/act on transition
                    self.logger.warning(
                        "Auth API down for %d polls — revoking auth.",
                        self._fail_streak
                    )
                    self.authenticated = False  # <-- same variable, set False

    # ------------------------------------------------------------------ #
    #  PACKET HANDLER — reads self.authenticated, never calls the API     #
    # ------------------------------------------------------------------ #

    def _learn_mac(self, dpid, mac, port):
        if dpid not in self.mac_to_port:
            self.mac_to_port[dpid] = collections.OrderedDict()
        table = self.mac_to_port[dpid]
        if mac in table:
            table.move_to_end(mac)
        else:
            if len(table) >= MAC_TABLE_MAX:
                old, _ = table.popitem(last=False)
                self.logger.debug("Evicted MAC %s from dpid %s", old, dpid)
            table[mac] = port

    def add_flow(self, datapath, priority, match, actions,
                 idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod  = parser.OFPFlowMod(
            datapath=datapath, priority=priority, match=match,
            instructions=inst, idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
        )
        datapath.send_msg(mod)

    def add_drop_flow(self, datapath, priority, match, idle_timeout=30):
        parser = datapath.ofproto_parser
        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath, priority=priority, match=match,
            instructions=[], idle_timeout=idle_timeout,
        ))

    def _drop_buffered_packet(self, datapath, msg):
        """Discard the packet currently held in the switch buffer."""
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        datapath.send_msg(parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=msg.match['in_port'],
            actions=[],
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None,
        ))

    # ---- Policy ---- #

    def _always_allowed(self, src_ip, dst_ip, tcp_pkt):
        pair = {src_ip, dst_ip}
        if pair == {CLIENT_IP, CONTROLLER_IP}:   return True
        if pair == {CONTROLLER_IP, GATEWAY_IP}:  return True
        if pair == {CONTROLLER_IP, CA_IP}:       return True
        if pair == {CA_IP, GATEWAY_IP}:          return True
        if VM_ROOT_IP in pair and CONTROLLER_IP in pair:
            if tcp_pkt is None:
                return True   # ARP / ICMP
            return tcp_pkt.src_port == 5000 or tcp_pkt.dst_port == 5000
        return False

    def _auth_allowed(self, src_ip, dst_ip):
        pair = {src_ip, dst_ip}
        if pair == {CLIENT_IP, GATEWAY_IP}:   return True
        if pair == {GATEWAY_IP, RESOURCE_IP}: return True
        return False

    def _is_allowed(self, src_ip, dst_ip, tcp_pkt):
        if self._always_allowed(src_ip, dst_ip, tcp_pkt):
            return True
        # Single bool read — no network call, no blocking
        if not self.authenticated:
            return False
        return self._auth_allowed(src_ip, dst_ip)

    # ---- Switch setup ---- #

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        # Priority 0 = table-miss (lowest); allow/deny rules use priority 50
        self.add_flow(datapath, 0, parser.OFPMatch(),
                      [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                              ofproto.OFPCML_NO_BUFFER)])
        self.logger.info("Table-miss installed on switch %s", datapath.id)

    # ---- Packet in ---- #

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg      = ev.msg
        datapath = msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        in_port  = msg.match['in_port']
        dpid     = datapath.id

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None or eth.ethertype == 0x88cc:   # drop LLDP
            return

        self._learn_mac(dpid, eth.src, in_port)

        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        arp_pkt  = pkt.get_protocol(arp.arp)
        tcp_pkt  = pkt.get_protocol(tcp.tcp)

        if ipv4_pkt:
            src_ip, dst_ip = ipv4_pkt.src, ipv4_pkt.dst
        elif arp_pkt:
            src_ip, dst_ip = arp_pkt.src_ip, arp_pkt.dst_ip
        else:
            return   # ignore non-IP, non-ARP

        # ---- Policy check: one bool read, no I/O ---- #
        if not self._is_allowed(src_ip, dst_ip, tcp_pkt):
            if ipv4_pkt:
                drop_match = parser.OFPMatch(eth_type=0x0800,
                                             ipv4_src=src_ip, ipv4_dst=dst_ip)
            else:
                drop_match = parser.OFPMatch(eth_type=0x0806,
                                             arp_spa=src_ip, arp_tpa=dst_ip)
            self.add_drop_flow(datapath, 50, drop_match, idle_timeout=30)
            self._drop_buffered_packet(datapath, msg)
            self.logger.info("DENY  %s -> %s on switch %s", src_ip, dst_ip, dpid)
            return

        # ---- Allowed: forward ---- #
        table    = self.mac_to_port.get(dpid, {})
        out_port = table.get(eth.dst, ofproto.OFPP_FLOOD)
        actions  = [parser.OFPActionOutput(out_port)]

        if ipv4_pkt:
            fwd_match = parser.OFPMatch(eth_type=0x0800,
                                        ipv4_src=src_ip, ipv4_dst=dst_ip)
        else:
            fwd_match = parser.OFPMatch(eth_type=0x0806,
                                        arp_spa=src_ip, arp_tpa=dst_ip)

        self.add_flow(datapath, 50, fwd_match, actions, idle_timeout=60)

        if ipv4_pkt:   # reverse flow for IPv4 only
            self.add_flow(datapath, 50,
                          parser.OFPMatch(eth_type=0x0800,
                                         ipv4_src=dst_ip, ipv4_dst=src_ip),
                          [parser.OFPActionOutput(in_port)],
                          idle_timeout=60)

        if out_port == ofproto.OFPP_FLOOD:
            self.logger.info("ALLOW %s -> %s via FLOOD (MAC %s unknown) on switch %s",
                             src_ip, dst_ip, eth.dst, dpid)
        else:
            self.logger.info("ALLOW %s -> %s via port %s on switch %s",
                             src_ip, dst_ip, out_port, dpid)

        datapath.send_msg(parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=msg.data,
        ))