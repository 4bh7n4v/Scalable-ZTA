from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ipv4, udp
from ryu.lib import hub

import json
import time
import logging
import threading

log = logging.getLogger('ZeroTrust')

# ─────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────

S1, S2, S3, S4 = 0x01, 0x02, 0x03, 0x04

# S1 ports
S1_CLIENT = 1
S1_PROXY  = 2
S1_S3     = 3

# S2 ports
S2_CTRL = 1
S2_GW   = 2

# S3 ports
S3_S1 = 1
S3_GW = 2

# S4 ports
S4_GW  = 1
S4_RES = 2

PORT_SPA      = 62201   # must match --listen-port in spa_pep_proxy.py
PORT_WG       = 51820
PROXY_IP      = '10.0.0.10'
PROXY_CMD_PORT = 7777

TTL = 300


# ─────────────────────────────────────────
# FLOW HELPERS
# ─────────────────────────────────────────

def add_flow(dp, priority, match, actions, idle=0, hard=0):
    ofp    = dp.ofproto
    parser = dp.ofproto_parser
    dp.send_msg(parser.OFPFlowMod(
        datapath     = dp,
        command      = ofp.OFPFC_ADD,
        priority     = priority,
        match        = match,
        instructions = [parser.OFPInstructionActions(
                            ofp.OFPIT_APPLY_ACTIONS, actions)],
        idle_timeout = idle,
        hard_timeout = hard,
        flags        = ofp.OFPFF_SEND_FLOW_REM,
    ))


def del_flow(dp, priority, match):
    ofp    = dp.ofproto
    parser = dp.ofproto_parser
    dp.send_msg(parser.OFPFlowMod(
        datapath  = dp,
        command   = ofp.OFPFC_DELETE_STRICT,
        priority  = priority,
        match     = match,
        out_port  = ofp.OFPP_ANY,
        out_group = ofp.OFPG_ANY,
    ))


def clear_flows(dp):
    ofp    = dp.ofproto
    parser = dp.ofproto_parser
    dp.send_msg(parser.OFPFlowMod(
        datapath  = dp,
        command   = ofp.OFPFC_DELETE,
        out_port  = ofp.OFPP_ANY,
        out_group = ofp.OFPG_ANY,
        match     = parser.OFPMatch(),
    ))


# ─────────────────────────────────────────
# BASELINE SWITCH FLOWS
# ─────────────────────────────────────────

def install_s1(dp):
    ofp    = dp.ofproto
    parser = dp.ofproto_parser
    clear_flows(dp)

    # ARP flood
    add_flow(dp, 200,
        parser.OFPMatch(eth_type=0x0806),
        [parser.OFPActionOutput(ofp.OFPP_FLOOD)])

    # SPA knock → forward to FrontProxy
    add_flow(dp, 100,
        parser.OFPMatch(eth_type=0x0800, ip_proto=17,
                        udp_dst=PORT_SPA),
        [parser.OFPActionOutput(S1_PROXY)])

    # Proxy command → Ryu controller
    add_flow(dp, 160,
        parser.OFPMatch(eth_type=0x0800, ip_proto=17,
                        in_port=S1_PROXY,
                        ipv4_src=PROXY_IP,
                        udp_dst=PROXY_CMD_PORT),
        [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)])

    # FrontProxy response → back to Client
    add_flow(dp, 150,
        parser.OFPMatch(eth_type=0x0800, ip_proto=17,
                        in_port=S1_PROXY,
                        ipv4_src=PROXY_IP),
        [parser.OFPActionOutput(S1_CLIENT)])

    # ── MISSING FLOW ADDED ────────────────────────────
    # Client → Gateway WireGuard handshake (tp_dst=51820)
    add_flow(dp, 100,
        parser.OFPMatch(eth_type=0x0800, ip_proto=17,
                        udp_dst=PORT_WG,
                        in_port=S1_CLIENT),
        [parser.OFPActionOutput(S1_S3)])
    # ─────────────────────────────────────────────────

    # WireGuard return path — Gateway → Client (tp_src=51820)
    add_flow(dp, 100,
        parser.OFPMatch(eth_type=0x0800, ip_proto=17,
                        udp_src=PORT_WG,
                        in_port=S1_S3),
        [parser.OFPActionOutput(S1_CLIENT)])

    # Default deny
    add_flow(dp, 10, parser.OFPMatch(), [])
    log.info('[S1] flows installed')
    
def install_s2(dp):
    ofp    = dp.ofproto
    parser = dp.ofproto_parser
    clear_flows(dp)

    # Drop management subnet noise
    add_flow(dp, 500,
        parser.OFPMatch(eth_type=0x0800, ipv4_src='10.0.3.100'), [])
    add_flow(dp, 500,
        parser.OFPMatch(eth_type=0x0806, arp_spa='10.0.3.100'), [])

    # ARP — Controller <-> Gateway only
    add_flow(dp, 300,
        parser.OFPMatch(eth_type=0x0806, in_port=S2_CTRL),
        [parser.OFPActionOutput(S2_GW)])
    add_flow(dp, 300,
        parser.OFPMatch(eth_type=0x0806, in_port=S2_GW),
        [parser.OFPActionOutput(S2_CTRL)])

    # mTLS Direction A: Controller → Gateway (4433)
    add_flow(dp, 300,
        parser.OFPMatch(eth_type=0x0800, ip_proto=6,
                        tcp_dst=4433, in_port=S2_CTRL),
        [parser.OFPActionOutput(S2_GW)])
    add_flow(dp, 300,
        parser.OFPMatch(eth_type=0x0800, ip_proto=6,
                        tcp_src=4433, in_port=S2_GW),
        [parser.OFPActionOutput(S2_CTRL)])

    # mTLS Direction B: Gateway → Controller (4434)
    add_flow(dp, 300,
        parser.OFPMatch(eth_type=0x0800, ip_proto=6,
                        tcp_dst=4434, in_port=S2_GW),
        [parser.OFPActionOutput(S2_CTRL)])
    add_flow(dp, 300,
        parser.OFPMatch(eth_type=0x0800, ip_proto=6,
                        tcp_src=4434, in_port=S2_CTRL),
        [parser.OFPActionOutput(S2_GW)])

    # Default deny
    add_flow(dp, 10, parser.OFPMatch(), [])
    log.info('[S2] flows installed')


def install_s3(dp):
    ofp    = dp.ofproto
    parser = dp.ofproto_parser
    clear_flows(dp)

    # ARP flood
    add_flow(dp, 200,
        parser.OFPMatch(eth_type=0x0806),
        [parser.OFPActionOutput(ofp.OFPP_FLOOD)])

    # Default deny — WireGuard flows added dynamically after auth
    add_flow(dp, 10, parser.OFPMatch(), [])
    log.info('[S3] flows installed')


def install_s4(dp):
    ofp    = dp.ofproto
    parser = dp.ofproto_parser
    clear_flows(dp)

    # ARP flood
    add_flow(dp, 200,
        parser.OFPMatch(eth_type=0x0806),
        [parser.OFPActionOutput(ofp.OFPP_FLOOD)])

    # Bidirectional forwarding: Gateway <-> Resource
    add_flow(dp, 100,
        parser.OFPMatch(eth_type=0x0800, in_port=S4_GW),
        [parser.OFPActionOutput(S4_RES)])
    add_flow(dp, 100,
        parser.OFPMatch(eth_type=0x0800, in_port=S4_RES),
        [parser.OFPActionOutput(S4_GW)])

    # Default deny
    add_flow(dp, 10, parser.OFPMatch(), [])
    log.info('[S4] flows installed')


# ─────────────────────────────────────────
# PER-CLIENT WIREGUARD PATH
# ─────────────────────────────────────────

def open_client(dp1, dp3, client_ip):
    parser = dp1.ofproto_parser

    # S1: client WireGuard → S3
    add_flow(dp1, 150,
        parser.OFPMatch(eth_type=0x0800, ip_proto=17,
                        ipv4_src=client_ip, udp_dst=PORT_WG),
        [parser.OFPActionOutput(S1_S3)],
        idle=TTL, hard=TTL)

    parser = dp3.ofproto_parser

    # S3: client → Gateway
    add_flow(dp3, 150,
        parser.OFPMatch(eth_type=0x0800, ip_proto=17,
                        ipv4_src=client_ip, udp_dst=PORT_WG, in_port=S3_S1),
        [parser.OFPActionOutput(S3_GW)],
        idle=TTL, hard=TTL)

    # S3: Gateway → client (return)
    add_flow(dp3, 150,
        parser.OFPMatch(eth_type=0x0800, ip_proto=17,
                        ipv4_dst=client_ip, udp_src=PORT_WG, in_port=S3_GW),
        [parser.OFPActionOutput(S3_S1)],
        idle=TTL, hard=TTL)

    log.info('[S1+S3] WireGuard flows installed for %s', client_ip)


def close_client(dp1, dp3, client_ip):
    parser = dp1.ofproto_parser
    del_flow(dp1, 150,
        parser.OFPMatch(eth_type=0x0800, ip_proto=17,
                        ipv4_src=client_ip, udp_dst=PORT_WG))

    parser = dp3.ofproto_parser
    del_flow(dp3, 150,
        parser.OFPMatch(eth_type=0x0800, ip_proto=17,
                        ipv4_src=client_ip, udp_dst=PORT_WG, in_port=S3_S1))
    del_flow(dp3, 150,
        parser.OFPMatch(eth_type=0x0800, ip_proto=17,
                        ipv4_dst=client_ip, udp_src=PORT_WG, in_port=S3_GW))

    log.info('[S1+S3] WireGuard flows removed for %s', client_ip)


# ─────────────────────────────────────────
# RYU APPLICATION
# ─────────────────────────────────────────

class ZeroTrustController(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._dps      = {}
        self._sessions = {}
        self._lock     = threading.Lock()
        hub.spawn(self._gc)
        log.info('[*] Zero Trust SDN Controller started')

    # ── Switch connects ──────────────────
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_connect(self, ev):
        dp   = ev.msg.datapath
        dpid = dp.id
        self._dps[dpid] = dp
        log.info('[*] Switch %s connected', hex(dpid))

        {S1: install_s1,
         S2: install_s2,
         S3: install_s3,
         S4: install_s4}.get(dpid, lambda dp: None)(dp)

        # Reinstall any active sessions if S1 reconnects
        if dpid == S1:
            self._reinstall_sessions()

    # ── Packet-In ───────────────────────
    # Only receives proxy command packets (UDP 7777 from FrontProxy)
    # Everything else is handled by hardware flows
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in(self, ev):
        msg  = ev.msg
        pkt  = packet.Packet(msg.data)
        ip4_ = pkt.get_protocol(ipv4.ipv4)
        udp_ = pkt.get_protocol(udp.udp)

        if not ip4_ or not udp_:
            return

        if ip4_.src != PROXY_IP or udp_.dst_port != PROXY_CMD_PORT:
            log.warning('[SDN] Unexpected packet-in src=%s port=%d — ignoring',
                        ip4_.src, udp_.dst_port)
            return

        try:
            # Calculate correct offset dynamically from parsed headers
            eth_len = 14
            ip_len  = ip4_.header_length * 4   # handles IP options
            udp_len = 8
            offset  = eth_len + ip_len + udp_len

            raw     = msg.data[offset:]
            log.info('[SDN] Raw UDP payload: %s', raw)
            command   = json.loads(raw.decode())
            action    = command.get('action', 'open')
            client_ip = command['client_ip']
            resource  = command['resource_ip']

        except json.JSONDecodeError as e:
            log.error('[SDN] JSON parse failed: %s — raw: %s', e, raw)
            return
        except KeyError as e:
            log.error('[SDN] Missing field: %s', e)
            return
        except Exception as e:
            log.error('[SDN] Bad proxy command: %s', e)
            return

        log.info('[SDN] Command: action=%s client=%s resource=%s',
                action, client_ip, resource)

        if action == 'open':
            self._open_network_path(client_ip, resource)
        elif action == 'close':
            self._close_network_path(client_ip)
        else:
            log.warning('[SDN] Unknown action: %s', action)
# ```

# ## Why This is Better Than Fixed `42`
# ```
# Fixed offset 42:
# eth=14 + ip=20 + udp=8 = 42  — only works if no IP options

# Dynamic offset:
# ip4_.header_length * 4  — correctly handles any IP header size
# eth=14 + ip=variable + udp=8  — always correct

    # ── Install flows for authorized client ──
    def _open_network_path(self, client_ip, resource):
        dp1 = self._dps.get(S1)
        dp3 = self._dps.get(S3)

        log.info('[SDN] Connected switches: %s', list(self._dps.keys()))
        log.info('[SDN] dp1=%s dp3=%s', dp1, dp3)

        if not dp1 or not dp3:
            log.error('[SDN] S1=%s S3=%s — one or both not connected', dp1, dp3)
            return

        with self._lock:
            if client_ip in self._sessions:
                log.info('[SDN] Replacing existing session for %s', client_ip)
                close_client(dp1, dp3, client_ip)

            self._sessions[client_ip] = {
                'resource'  : resource,
                'expires_at': time.time() + TTL,
            }

        open_client(dp1, dp3, client_ip)
        log.info('[SDN] Network path opened: %s → %s', client_ip, resource)

    # ── Remove flows for a client ────────
    def _close_network_path(self, client_ip):
        dp1 = self._dps.get(S1)
        dp3 = self._dps.get(S3)
        if not dp1 or not dp3:
            return

        with self._lock:
            self._sessions.pop(client_ip, None)

        close_client(dp1, dp3, client_ip)
        log.info('[SDN] Network path closed: %s', client_ip)

    # ── Flow expired by TTL ──────────────
    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed(self, ev):
        msg   = ev.msg
        match = msg.match
        if msg.datapath.id == S1 and msg.priority == 150:
            client_ip = match.get('ipv4_src')
            if client_ip and match.get('udp_dst') == PORT_WG:
                log.info('[SDN] Flow TTL expired for %s — removing session', client_ip)
                dp3 = self._dps.get(S3)
                if dp3:
                    close_client(msg.datapath, dp3, client_ip)
                self._sessions.pop(client_ip, None)

    # ── Reinstall flows after S1 reconnect ──
    def _reinstall_sessions(self):
        dp1 = self._dps.get(S1)
        dp3 = self._dps.get(S3)
        if not dp1 or not dp3:
            return
        for ip in list(self._sessions.keys()):
            open_client(dp1, dp3, ip)
        log.info('[SDN] Reinstalled %d session flows', len(self._sessions))

    # ── GC: remove expired sessions ─────
    def _gc(self):
        while True:
            hub.sleep(60)
            now     = time.time()
            expired = [ip for ip, s in self._sessions.items()
                       if now > s['expires_at']]
            for ip in expired:
                self._close_network_path(ip)
                log.info('[GC] Session expired and removed: %s', ip)