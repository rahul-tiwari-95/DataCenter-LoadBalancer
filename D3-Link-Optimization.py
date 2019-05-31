from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
# You may import more libs here, but the above libs should be enough


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]


    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        # arp table: for searching
        self.arp_table={}
        ### fill in the table for arp searching
        ### e.g. self.arp_table["10.0.0.1"] = "00:00:00:00:00:01";
        self.arp_table["10.0.0.1"]="00:00:00:00:00:01"
        self.arp_table["10.0.0.2"]="00:00:00:00:00:02"
        self.arp_table["10.0.0.3"]="00:00:00:00:00:03"
        self.arp_table["10.0.0.4"]="00:00:00:00:00:04"
        self.arp_table["10.0.0.5"]="00:00:00:00:00:05"
        #S1, S2, S3 Mac is needed to implement Load balancing code
        S1_MAC = "00:00:00:00:00:01"
        S2_MAC = "00:00:00:00:00:02"
        S3_MAC = "00:00:00:00:00:03"


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install the table-miss flow entry.
        #If the new flow isnt recognized , then do OFPMatch()
        #Two conditions :
        #If the incoming Flow is TCP and not recongzied
        # Or, incoming flow is not TCP and not recognized
        if(parser.OFPMatch(eth_type = ether.ETH_TYPE_IP):
            dpid = datapath.id #Classifying Switch ID
            if dpid == 4: #Switch S4
                actions=[parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)]
                self.add_flow(datapath,20,match,actions)

            elif dpid == 5: #Switch S5
                actions=[parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)]
                self.add_flow(datapath,20,match,actions)
            else: 
                 match = parser.OFPMatch()
                 #Don't do anything if the new TCP flow isn't on S4 or S5



        else:
            # Non TCP Flows goes there
            match = parser.OFPMatch()
            #Don't do anything if it is a Non-TCP FLow 
            #x 






    
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # construct flow_mod message and send it.
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)




    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
       msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # get Datapath ID to identify OpenFlow switches.
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # analyse the received packets using the packet library.
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4) # parse out the IPv4 pkt
        tcp_pkt = ipv4_pkt.get_protocol(tcp.tcp) #Extract TCP Data
        #Extracting Source & Destination 
        dst = tcp_pkt.dst
        src = tcp_pkt.src

        #Apply Load Balanicng Code here
        #Even packet number goes to S2
        #Odd packet number goes to S1 and S3

        count = 0 #Counter to track how many packets came in

       #First Check that whether it's S4 or S5?
            
        if (dpid == 4 or dpid == 5):
            if(count%3 == 0):
                #Send packet to S3
                #We assume that it redirects packet from S4 and S5 to S3
                #See the diagram for port number reference
                #4 is the output port
                #1 is the input port
                  actions = [parser.OFPActionOutput(4)]
                  match = parser.OFPMatch(in_port = 1,
                                    eth_type = ether.ETH_TYPE_IP)
                  self.add_flow(datapath, 30, match, actions)
            elif(count%2==0):
                #send packet to S2
                #3 is the output port

                actions = [parser.OFPActionOutput(3)]
                match = parser.OFPMatch(in_port = 1,
                                    eth_type = ether.ETH_TYPE_IP)
                self.add_flow(datapath, 30, match, actions)

            else:
                #send packet to S1
                #2 is the Output port
                actions = [parser.OFPActionOutput(2)]
                match = parser.OFPMatch(in_port = 1,
                                    eth_type = ether.ETH_TYPE_IP)
                self.add_flow(datapath, 30, match, actions)

        else:
            #Drop the packet
            #Do nothing 



                
                
                





    

        # get the received port number from packet_in message.
       
         in_port = msg.match['in_port']

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        # if the destination mac address is already learned,
        # decide which port to output the packet, otherwise FLOOD.
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        # construct action list.
        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time.
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        # construct packet_out message and send it.
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions,
                                  data=msg.data)
        datapath.send_msg(out)