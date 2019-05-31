from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.ofproto import inet
import json
# packet
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, arp, ipv4, tcp
import time
import csv


class shortest_path(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]


    def __init__(self, *args, **kwargs):
        super(shortest_path, self).__init__(*args, **kwargs)
        self.arp_table = {}
        self.arp_table = {'10.0.0.1': '00:00:00:00:00:01',
                          '10.0.0.2': '00:00:00:00:00:02',
                          '10.0.0.3': '00:00:00:00:00:03'}
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.list42 = []
        self.list43 = []
        self.list32 = []
        self.list33 = []
        self.i = 0
        self.j = 0
        self.x = 0
        self.y = 0
    # Initial handshake between switchand controller proactive entries are added to switch here

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser  # parser

        # this code does default match and sends flows that default packet should be send to controller
        match = ofp_parser.OFPMatch()
        action = ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                  [ofp_parser.OFPActionOutput(ofp.OFPP_CONTROLLER)])
        inst = [action]
        self.add_flow(dp=dp, match=match, inst=inst, table=0, priority=0)

        # Add here proactive icmp rules
        dpid = dp.id

        if (dpid == 1):  # Switch One
            self.flow_match_aggr(dp, '10.0.0.2', inet.IPPROTO_UDP, 2)
            self.flow_match_aggr(dp, '10.0.0.3', inet.IPPROTO_UDP, 3)
            self.flow_match_aggr(dp, '10.0.0.1', inet.IPPROTO_UDP, 1)

        if (dpid == 2):  # Switch One
            self.flow_match_aggr(dp, '10.0.0.2', inet.IPPROTO_UDP, 2)
            self.flow_match_aggr(dp, '10.0.0.3', inet.IPPROTO_UDP, 3)
            self.flow_match_aggr(dp, '10.0.0.1', inet.IPPROTO_UDP, 1)

        if (dpid == 3):  # Switch Three
            self.flow_match_edge(dp, '10.0.0.2', inet.IPPROTO_UDP, 2)
            self.flow_match_edge(dp, '10.0.0.3', inet.IPPROTO_UDP, 2)

        if (dpid == 4):  # Switch Four
            self.flow_match_edge(dp, '10.0.0.3', inet.IPPROTO_UDP, 2)

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

        # self.logger.info("this is datapath dictionary:")
        # self.logger.info(self.datapaths)

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                # self.logger.info(dp.id)
                if dp.id == 3 or dp.id == 4:
                    #self.logger.info("Request for switch %d links is made", dp.id)
                    self._request_stats(dp)
            hub.sleep(10)

    def _request_stats(self, datapath):
        # self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        '''
        req = self.send_flow_stats_request(datapath)
        datapath.send_msg(req)
        self.logger.info("Following this is flow stats request send")
        self.logger.info(req) '''

        # req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        # datapath.send_msg(req)
        # self.logger.info(req)
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)
        #self.logger.info("Following this is flow stats request send")
        #self.logger.info(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):

        body = ev.msg.body

        '''self.logger.info('datapath         port     '
                         'rx-pkts  rx-bytes rx-error '
                         'tx-pkts  tx-bytes tx-error')
        self.logger.info('---------------- -------- '
                         '-------- -------- -------- '
                         '-------- -------- --------')'''
        # self.logger.info(body)
        for stat in body:
            '''self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',
                             ev.msg.datapath.id, stat.port_no,
                             stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                             stat.tx_packets, stat.tx_bytes, stat.tx_errors)'''
            now = time.time()

            readings = {"switch": ev.msg.datapath.id, "portno": stat.port_no, "rxbytes": stat.rx_bytes,
                        "tx_bytes": stat.tx_bytes, "time": now}



            if ev.msg.datapath.id == 4 and stat.port_no == 2 :
                #self.logger.info("42")
                readings = {"switch": ev.msg.datapath.id, "portno": stat.port_no, "rxbytes": stat.rx_bytes,
                            "tx_bytes": stat.tx_bytes, "time": now}
                self.list42.append(readings)
                f = open("final42.csv", "a")
                f.write(str(ev.msg.datapath.id) + "," + str(stat.port_no) + "," + str(stat.rx_bytes) + "," + str(stat.tx_bytes) + "," + str(now) + "\n")  # str() converts to string
                f.close()

                self.i = self.i + 1
                if (self.i == 2):
                    #self.logger.info(self.list42)
                    self.loadcalc42(self.list42)



            if ev.msg.datapath.id == 4 and stat.port_no == 3 :
                #self.logger.info("43")
                readings = {"switch": ev.msg.datapath.id, "portno": stat.port_no, "rxbytes": stat.rx_bytes,
                            "tx_bytes": stat.tx_bytes, "time": now}
                self.list43.append(readings)
                f = open("final43.csv", "a")
                f.write(str(ev.msg.datapath.id) + "," + str(stat.port_no) + "," + str(stat.rx_bytes) + "," + str(stat.tx_bytes) + "," + str(now) + "\n")  # str() converts to string
                f.close()
                self.j = self.j + 1
                if (self.j == 2):
                    #self.logger.info(self.list43)
                    self.loadcalc43(self.list43)



            if ev.msg.datapath.id == 3 and stat.port_no == 2:
                #self.logger.info("32")
                readings = {"switch": ev.msg.datapath.id, "portno": stat.port_no, "rxbytes": stat.rx_bytes,
                            "tx_bytes": stat.tx_bytes, "time": now}
                self.list32.append(readings)
                f = open("final32.csv", "a")
                f.write(str(ev.msg.datapath.id) + "," + str(stat.port_no) + "," + str(stat.rx_bytes) + "," + str(stat.tx_bytes) + "," + str(now) + "\n")  # str() converts to string
                f.close()
                self.x = self.x + 1
                if (self.x == 2):
                    #self.logger.info(self.list32)
                    self.loadcalc32(self.list32)


            if ev.msg.datapath.id == 3 and stat.port_no == 3:
                #self.logger.info("33")
                readings = {"switch": ev.msg.datapath.id, "portno": stat.port_no, "rxbytes": stat.rx_bytes,
                            "tx_bytes": stat.tx_bytes, "time": now}
                self.list33.append(readings)
                f = open("final33.csv", "a")
                f.write(str(ev.msg.datapath.id) + "," + str(stat.port_no) + "," + str(stat.rx_bytes) + "," + str(stat.tx_bytes) + "," + str(now) + "\n")  # str() converts to string
                f.close()
                self.y = self.y + 1
                if (self.y == 2):
                    #self.logger.info(self.list33)
                    self.loadcalc33(self.list33)


    #Code for load balancing on the basis of Link Util
    # On the basis of received and transmitted bytes

    def loadcalc42(self,list):

        #print(list)
        utilization42 = ((list[1]['rxbytes']-list[0]['rxbytes']) + (list[1]['tx_bytes']-list[0]['tx_bytes'])) / 10
        print("utilization of switch 4 port 2 is : ")
        print(utilization42)
        list.pop(0)
        self.i = 1

    def loadcalc43(self,list):

        #print(list)
        utilization43 = ((list[1]['rxbytes']-list[0]['rxbytes']) + (list[1]['tx_bytes']-list[0]['tx_bytes'])) / 10
        print("utilization of switch 4 port 3 is : ")
        print(utilization43)
        list.pop(0)
        self.j = 1

    def loadcalc32(self,list):

        #print(list)
        utilization32 = ((list[1]['rxbytes']-list[0]['rxbytes']) + (list[1]['tx_bytes']-list[0]['tx_bytes'])) / 10
        print("utilization of switch 3 port 2 is : ")
        print(utilization32)
        list.pop(0)
        self.x = 1

    def loadcalc33(self,list):

        #print(list)
        utilization33 = ((list[1]['rxbytes']-list[0]['rxbytes']) + (list[1]['tx_bytes']-list[0]['tx_bytes'])) / 10
        print("utilization of switch 3 port 3 is : ")
        print(utilization33)
        list.pop(0)
        self.y = 1




    def send_flow_stats_request(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        match = ofp_parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ip_proto=inet.IPPROTO_UDP)
        req = ofp_parser.OFPFlowStatsRequest(datapath, match=match)
        return req

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        self.logger.info("This is flow stats reply for switch %d", ev.msg.datapath.id)
        # self.logger.info(body)
        for stat in body:
            self.logger.info(stat)
        '''self.logger.info('datapath         '
                         'in-port  eth-dst           '
                         'out-port packets  bytes')
        self.logger.info('---------------- '
                         '-------- ----------------- '
                         '-------- -------- --------')
        for stat in sorted([flow for flow in body if flow.priority == 10],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):
            self.logger.info('%016x %8x %17s %8x %8d %8d',
                             ev.msg.datapath.id,
                             stat.match['in_port'], stat.match['eth_dst'],
                             stat.instructions[0].actions[0].port,
                             stat.packet_count, stat.byte_count)'''

    def flow_match_edge(self, dp, ipv4_dst, proto, out_port):
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser
        match = ofp_parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_dst=ipv4_dst, ip_proto=proto)
        action = ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                  [ofp_parser.OFPActionOutput(out_port)])
        inst = [action]
        self.add_flow(dp, match, inst, 0, 10)

    def flow_match_aggr(self, dp, ipv4_dst, proto, out_port):
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser
        match = ofp_parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_dst=ipv4_dst, ip_proto=proto)
        action = ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                  [ofp_parser.OFPActionOutput(out_port)])
        inst = [action]
        self.add_flow(dp, match, inst, 0, 10)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        # self.logger.info(ev)
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser

        # get datapath ID to identify OpenFLow Switches
        dpid = dp.id
        # analyse the received packets using packet library to take appropriate action
        pkt = packet.Packet(msg.data)
        # self.logger.info("This is packet in message!")
        # self.logger.info(pkt)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        ethertype = eth_pkt.ethertype
        eth_dst = eth_pkt.dst
        eth_src = eth_pkt.src

        in_port = msg.match['in_port']

        # self.logger.info("This is packet_in from switch id %s",dpid)
        # self.logger.info("packet in ether_type = %s dpid = %s, src =  %s, dst =  %s, in_port =  %s ",ethertype, dpid, eth_src, eth_dst, in_port)

        # If arp packet send to handle_arp
        if (ethertype == ether.ETH_TYPE_ARP):
            self.handle_arp(dp, in_port, pkt)

        # If packet is TCP sync from H2 and H4 then Send RST message

    # if (ethertype == ether.ETH_TYPE_IP):
    #  self.handle_tcp(dp, in_port, pkt)

    # FlowMod for adding proactive flows in to switch

    def add_flow(self, dp, match, inst, table, priority):
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser

        buffer_id = ofp.OFP_NO_BUFFER

        mod = ofp_parser.OFPFlowMod(
            datapath=dp, table_id=table, priority=priority,
            match=match, instructions=inst
        )
        # self.logger.info("Here are flows")
        # self.logger.info(mod)
        dp.send_msg(mod)

    # PacketOut used to send packet from controller to switch

    def send_packet(self, dp, port, pkt):
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        pkt.serialize()
        data = pkt.data
        action = [parser.OFPActionOutput(port=port)]

        out = parser.OFPPacketOut(
            datapath=dp, buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=action, data=data)
        dp.send_msg(out)

    # In our case arp table is hardcoded so arprequest is resolved by controller

    def handle_arp(self, dp, port, pkt):
        pkt_arp = pkt.get_protocol(arp.arp)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)

        # checking if it's arp packet return None if not arp packet
        if pkt_arp.opcode != arp.ARP_REQUEST:
            return

        # checking if the destination address exists in arp_table returns NONE otherwise
        if self.arp_table.get(pkt_arp.dst_ip) == None:
            return

        get_mac = self.arp_table[pkt_arp.dst_ip]

        pkt = packet.Packet()
        pkt.add_protocol(
            ethernet.ethernet(
                ethertype=ether.ETH_TYPE_ARP,
                dst=pkt_ethernet.src,
                src=get_mac
            )
        )

        pkt.add_protocol(
            arp.arp(
                opcode=arp.ARP_REPLY,
                src_mac=get_mac,
                src_ip=pkt_arp.dst_ip,
                dst_mac=pkt_arp.src_mac,
                dst_ip=pkt_arp.src_ip
            )
        )

        self.send_packet(dp, port, pkt)
