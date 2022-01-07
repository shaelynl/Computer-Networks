'''
Please add your name: SHAELYN LAM
Please add your matric number: A0203271W
'''

import sys
import os
from sets import Set

from pox.core import core

import pox.openflow.libopenflow_01 as of
import pox.openflow.discovery
import pox.openflow.spanning_forest

from pox.lib.revent import *
from pox.lib.util import dpid_to_str
from pox.lib.addresses import IPAddr, EthAddr

import datetime

log = core.getLogger()

TTL = 10
IDLE_TTL = TTL
HARD_TTL = TTL

REGULAR = 0
PREMIUM = 1

FIREWALL_PRIORITY = 200
QOS_PRIORITY = 100

class Controller(EventMixin):
    def __init__(self):
        self.listenTo(core.openflow)
        core.openflow_discovery.addListeners(self)
        self.macport = {}
        self.macport_ttl = {}
        self.premiumTable = []

    def _handle_PacketIn (self, event):

        def host_ip_to_mac(hostip):
            hostid = int(str(hostip).split('.')[-1])
            hostmac = EthAddr("%012x" % (hostid & 0xffFFffFFffFF,))
            return hostmac

        # Update Mac to Port table mapping
        def learn_table():
            if dpid not in self.macport:
                self.macport[dpid] = {}
                self.macport_ttl[dpid] = {}

            if src_mac not in self.macport[dpid]:
                log.debug("** Switch %i: Learning... MAC: %s, Port: %s" % (dpid, src_mac, inport))
                self.macport[dpid][src_mac] = inport
                self.macport_ttl[dpid][src_mac] = datetime.datetime.now()

        def clear_table():
            if dst_mac in self.macport_ttl[dpid] and self.macport_ttl[dpid][dst_mac] + datetime.timedelta(seconds=TTL) <= datetime.datetime.now():
                log.debug("** Switch %i: Timeout!... Remove MAC: %s, Port: %s" % (dpid, dst_mac, self.macport[dpid][dst_mac]))
                self.macport[dpid].pop(dst_mac)
                self.macport_ttl[dpid].pop(dst_mac)

        def is_premium(srcIp):
            # log.debug(self.premiumTable)
            if srcIp in self.premiumTable:
                return True
            else:
                return False

    	# install entries to the route table
        def install_enqueue(event, packet, outport, q_id):
            log.debug("** Switch %i: Installing flow %s.%i -> %s.%i", dpid, src_mac, inport, dst_mac, outport)
            msg = of.ofp_flow_mod()
            msg.match = of.ofp_match.from_packet(packet, inport)
            msg.priority = QOS_PRIORITY
            if is_premium(src_ip) or is_premium(dst_ip):
                log.debug("adding to premium %s", src_ip)
                action = of.ofp_action_enqueue(port = outport, queue_id = PREMIUM)
            else:
                log.debug("adding to regular %s", src_ip)
                action = of.ofp_action_enqueue(port = outport)
            msg.actions.append(action)
            msg.data = event.ofp
            msg.idle_timeout = IDLE_TTL
            msg.hard_timeout = HARD_TTL
            event.connection.send(msg)
            log.debug("** Switch %i: Rule sent: Outport %i, Queue %i", dpid, outport, q_id)
            return

    	# Check the packet and decide how to route the packet
        def forward(message = None):
            if dst_mac.is_multicast: return flood("** Switch %s: Multicast -- %s" % (dpid, packet))
            if dst_mac not in self.macport[dpid]: return flood("** Switch %s: Port for %s unknown -- flooding" % (dpid, dst_mac,))

            q_id = get_q_id(str(src_ip), str(dst_ip))
            outport = self.macport[dpid][dst_mac]
            install_enqueue(event, packet, outport, q_id)
            return

        def get_q_id(src_ip, dst_ip):
            src_q_id = get_ip_q_id(src_ip)
            dst_q_id = get_ip_q_id(dst_ip)
            if src_q_id == PREMIUM or dst_q_id == PREMIUM: return PREMIUM
            else: return REGULAR

        def get_ip_q_id(ip):
            if ip in self.premiumTable: return PREMIUM
            else: return REGULAR

        def flood (message = None):
            log.debug(message)
            msg = of.ofp_packet_out()
            msg.data = event.ofp
            msg.in_port = inport
            msg.actions.append(of.ofp_action_output(port = of.OFPP_ALL))
            event.connection.send(msg)
            log.debug("Switch %s: Flood packet, DstIP: %s" % (dpid, dst_ip))
            return

        packet  = event.parsed   # This is the parsed packet data
        dpid    = event.dpid     # This is the switch
        inport  = event.port     # This is the port that the packet came from
        src_mac = packet.src     # This is the source's MAC address
        dst_mac = packet.dst     # This is the destination's MAC address

        if packet.type == packet.IP_TYPE:
            src_ip = packet.payload.srcip
            dst_ip = packet.payload.dstip
        elif packet.type == packet.ARP_TYPE:
            src_ip = packet.payload.protosrc
            dst_ip = packet.payload.protodst
            if dst_mac.is_multicast:
                dst_mac = host_ip_to_mac(dst_ip)

        learn_table()
        forward()
        clear_table()


    def _handle_ConnectionUp(self, event):
        dpid = dpid_to_str(event.dpid)
        log.debug("Switch %s has come up.", dpid)

        def readPoliciesFromFile(file):
            fw_policies = []
            with open(file) as f:
                index = 0
                for line in f:
                    line = line.strip("\n ' '")
                    if index == 0:
                        firstLineItems = line.split(' ')
                        numRowFirewall = int(firstLineItems[0])
                        numRowPreimum = int(firstLineItems[1])
                    elif (numRowFirewall >= index):
                        items = line.split(',')
                        if len(items) == 2:
                            fw_policies.append((None, items[0], items[1]))
                        else:
                            fw_policies.append(items)
                    else:
                        self.premiumTable.append(line)
                    index +=1
                log.debug(self.premiumTable)
            return fw_policies

        # Send the firewall policies to the switch
        def sendFirewallPolicy(connection, policy):
            from_IP, to_IP, to_port = policy
            log.debug("** Switch %s: Adding Firewall Rule Src: %s, Dst: %s:%s" % (dpid, from_IP, to_IP, to_port))
            msg = of.ofp_flow_mod()
            msg.priority = FIREWALL_PRIORITY
            # msg.actions.append(of.ofp_action_output(port = of.OFPP_NONE))
            msg.match.dl_type = 0x800
            msg.match.nw_proto = 6
            if from_IP: msg.match.nw_src = IPAddr(from_IP)
            if to_IP:
                msg.match.nw_dst = IPAddr(to_IP)
                msg.match.tp_dst = int(to_port)
            connection.send(msg)
            log.debug("** Switch %s: Firewall Rule added!" % (dpid, ))
        fw_policies = readPoliciesFromFile("policy.in")
        for fw_policy in fw_policies:
            sendFirewallPolicy(event.connection, fw_policy)


def launch():
    # Run discovery and spanning tree modules
    pox.openflow.discovery.launch()
    pox.openflow.spanning_forest.launch()

    # Starting the controller module
    core.registerNew(Controller)
