from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4, udp, arp
from ryu.lib.packet import ether_types
from ryu.controller import dpset
#from threading import Timer

class SS13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'dpset': dpset.DPSet}

    def __init__(self, *args, **kwargs):
        super(SS13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.arp_count=0
        self.dpset=kwargs['dpset']
        self.no_switches=0
        self.dscp_value=15
        #self.t=None  #thread

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.no_switches=self.no_switches+1

        #------------------- table 0 ---------------------#
        #self.logger.info("\n\t\t***It was ARP reply***\n")
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, udp_src=335, ip_proto=17)
        inst = [parser.OFPInstructionGotoTable(1)]
        mod = parser.OFPFlowMod(datapath=datapath, table_id=0, priority= 2, match=match, instructions=inst)
        datapath.send_msg(mod)
        
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, udp_src=635, ip_proto=17)
        inst = [parser.OFPInstructionGotoTable(4)]
        mod = parser.OFPFlowMod(datapath=datapath, table_id=0, priority= 2, match=match, instructions=inst)
        datapath.send_msg(mod)
        #--------------------- table 1 --------------------#
        for i in range (4,15):
            ip_dscp=i>>2
            match = parser.OFPMatch(eth_type = ether_types.ETH_TYPE_IP, ip_dscp=ip_dscp)
            inst = []
            mod = parser.OFPFlowMod(datapath=datapath, table_id=1, priority= 1, match=match, instructions=inst)
            datapath.send_msg(mod)
            
        match = parser.OFPMatch()
        inst = [parser.OFPInstructionGotoTable(2)]
        mod = parser.OFPFlowMod(datapath=datapath, table_id=1, priority= 0, match=match, instructions=inst)
        datapath.send_msg(mod)
        print("done here")
        '''
        #--------------------- table 2 --------------------#
        i=0
        for i in range (4,15):
            ip_dscp=i>>2
            ports = datapath.ports
            if not ports:
                print("No ports found.")
            else:
                for port in ports.values():
                   print(port)

            print("done here 2")
            port = 0
            print("port = 0")
            for port in ports.values():
                print("\nLOOP\n")
                port_number = port.port_no
                print("Port number:", port_number)
                match = parser.OFPMatch(eth_type = ether_types.ETH_TYPE_IP, ip_dscp=ip_dscp, in_port = port_number)
                inst = []
                mod = parser.OFPFlowMod(datapath=datapath, table_id=2, priority= 2, match=match, instructions=inst)
                datapath.send_msg(mod)
        
        match = parser.OFPMatch()
        inst = [parser.OFPInstructionGotoTable(3)]
        mod = parser.OFPFlowMod(datapath=datapath, table_id=2, priority= 1, match=match, instructions=inst)
        datapath.send_msg(mod)
        '''

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("\nmac_to_port\n %s\n",self.mac_to_port)
        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
                #--------------------- table 2 --------------------#
                
                for i in range (4,15):
                    ip_dscp=i>>2
                    ports = datapath.ports
                    if not ports:
                        print("No ports found.")
                    else:
                        for port in ports.values():
                           print(port)

                    print("done here 2")
                    port = 0
                    print("port = 0")
                    
                    for port in ports.values():
                        print("\nLOOP\n")
                        port_number = port.port_no
                        print("Port number:", port_number)
                        match = parser.OFPMatch(eth_type = ether_types.ETH_TYPE_IP, ip_dscp=ip_dscp, in_port = port_number)
                        inst = []
                        mod = parser.OFPFlowMod(datapath=datapath, table_id=2, priority= 2, match=match, instructions=inst)
                        datapath.send_msg(mod)
                
                match = parser.OFPMatch()
                inst = [parser.OFPInstructionGotoTable(3)]
                mod = parser.OFPFlowMod(datapath=datapath, table_id=2, priority= 1, match=match, instructions=inst)
                datapath.send_msg(mod)
                #--------------------- table 3 --------------------#
                match = parser.OFPMatch(eth_dst=dst,in_port = in_port)
                actions = [parser.OFPActionOutput(out_port)]
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                mod = parser.OFPFlowMod(datapath=datapath, table_id=3, priority= 1, match=match, instructions=inst)
                datapath.send_msg(mod)
                
                #--------------------- table 4 --------------------#
                for i in range (15,30):
                    ip_dscp=i>>2
                    match = parser.OFPMatch(eth_type = ether_types.ETH_TYPE_IP, ip_dscp=ip_dscp, in_port = in_port)
                    actions = [parser.OFPActionOutput(out_port)]
                    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                    mod = parser.OFPFlowMod(datapath=datapath, table_id=4, priority= 1, match=match, instructions=inst)
                    datapath.send_msg(mod)
        
        
        arp_head = pkt.get_protocol(arp.arp)
        ip_head = pkt.get_protocol(ipv4.ipv4)
        '''
        if arp_head:
            data = None
            #self.arp_count = self.arp_count + 1
            #self.logger.info("\n\t\t***It was ARP request***\narp_count = %d",self.arp_count)
            #self.t.join()
            
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
            
            if arp_head.opcode == 1:
                self.logger.info("\n\t\t***It was ARP request***\n")
            else:
                self.logger.info("\n\t\t***It was ARP reply***\n")
                #--------------------- table 3 --------------------#
                match = parser.OFPMatch(eth_dst=dst,in_port = in_port)
                actions = [parser.OFPActionOutput(out_port)]
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                mod = parser.OFPFlowMod(datapath=datapath, table_id=3, priority= 1, match=match, instructions=inst)
                datapath.send_msg(mod)
            
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
            
            if arp_head.opcode == 1:
                self.logger.info("\n\t\t***It was ARP request***\n")
            else:
                self.logger.info("\n\t\t***It was ARP reply***\n")
            
            switches=3
            if self.arp_count ==1:
                for i in range (1,self.no_switches+1):
                    
                    #------------------- table 0 ---------------------#
                    dtpt=self.dpset.get(i)
                    ofproto = dtpt.ofproto
                    parser=dtpt.ofproto_parser
                    self.logger.info("\n\t\t***It was ARP reply***\n")
                    #ofproto = dtpt.ofproto
                    #parser=dtpt.ofproto_parser
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, udp_src=335, ip_proto=17)
                    inst = [parser.OFPInstructionGotoTable(1)]
                    mod = parser.OFPFlowMod(datapath=dtpt, table_id=0, priority= 2, match=match, instructions=inst)
                    dtpt.send_msg(mod)
                    
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, udp_src=635, ip_proto=17)
                    inst = [parser.OFPInstructionGotoTable(4)]
                    mod = parser.OFPFlowMod(datapath=dtpt, table_id=0, priority= 2, match=match, instructions=inst)
                    dtpt.send_msg(mod)
                    
                    #--------------------- table 1 --------------------#
                    for i in range (1,30):
                        ip_dscp=i>>2
                        match = parser.OFPMatch(eth_type = ether_types.ETH_TYPE_IP, ip_dscp=ip_dscp)
                        inst = []
                        mod = parser.OFPFlowMod(datapath=dtpt, table_id=1, priority= 1, match=match, instructions=inst)
                        dtpt.send_msg(mod)
                        
                    match = parser.OFPMatch()
                    inst = [parser.OFPInstructionGotoTable(2)]
                    mod = parser.OFPFlowMod(datapath=dtpt, table_id=1, priority= 1, match=match, instructions=inst)
                    dtpt.send_msg(mod)
                    
                    #--------------------- table 2 --------------------#
                    for i in range (1,30):
                        # *** drop the packet *** #
                        ip_dscp=i>>2
                        match = parser.OFPMatch(eth_type = ether_types.ETH_TYPE_IP, ip_dscp=ip_dscp, in_port = in_port)
                        inst = []
                        mod = parser.OFPFlowMod(datapath=dtpt, table_id=2, priority= 2, match=match, instructions=inst)
                        dtpt.send_msg(mod)
                        
                    match = parser.OFPMatch()
                    inst = [parser.OFPInstructionGotoTable(3)]
                    mod = parser.OFPFlowMod(datapath=dtpt, table_id=2, priority= 1, match=match, instructions=inst)
                    dtpt.send_msg(mod)
                    
                    #--------------------- table 3 --------------------#
                    match = parser.OFPMatch()
                    actions = [parser.OFPActionOutput(out_port)]
                    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                    mod = parser.OFPFlowMod(datapath=dtpt, table_id=2, priority= 1, match=match, instructions=inst)
                    dtpt.send_msg(mod)
                    
                    #--------------------- table 4 --------------------#
                    
                    #ports = self.dpset.get_ports(i)
                    host_ports = self.get_all_host_ports()
                    
                    
                    match = parser.OFPMatch(eth_type = ether_types.ETH_TYPE_IP, ip_dscp=ip_dscp, in_port = in_port)
                    actions = [parser.OFPActionOutput(out_port)]
                    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                    mod = parser.OFPFlowMod(datapath=dtpt, table_id=2, priority= 1, match=match, instructions=inst)
                    dtpt.send_msg(mod)
                    
                
                
                self.logger.info("\nflow installed\n")
                
                
                
                
        
        
        
        '''
        
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
