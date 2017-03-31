#
# Copyright 2013 Liu Weiyu
#

"""
A switch which realizes ip mutation to protect the internal node

For each switch:
1) When get an arp request for internal node from any external node, change the destination ip to the real ip of internal node and forward the request to the internal node.
2) When get an arp reply from internal node, change the source real ip into the virtual ip and forward the reply to the related destination external node.
3) When get an icmp request from external node, install an entry into the switch to change the destination ip to real ip of the internal node, set the destination mac address and switch port related to the internal node.
4) When get an icmp reply from internal node, install an entry into the switch to change the srcip into virtual ip of the internal node, set the mac addr and switch port for the destinated external node.
"""

from pox.core import core
import pox
log = core.getLogger()

#from pox.ext.topology import exp-topo2
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.packet.dns import dns
from pox.lib.packet.udp import udp
from pox.lib.packet.icmp import icmp
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import str_to_bool, dpidToStr
from pox.lib.recoco import Timer
from pox.lib.revent import *

import pox.openflow.libopenflow_01 as of
import numpy as np

import threading
import time
import copy

import random

# Timeout for flows
FLOW_IDLE_TIMEOUT = 10

# Timeout for ARP entries
ARP_TIMEOUT = 60 * 2

# Maximum number of packet to buffer on a switch for an unknown IP
MAX_BUFFERED_PER_IP = 5

# Maximum time to hang on to a buffer for an unknown IP in seconds
MAX_BUFFER_TIME = 5

# Real Ip of the internal host
REAL_IP_OF_INTERNAL_HOST = ['10.0.0.1','10.0.0.2','10.0.0.3','10.0.0.4','10.0.0.5','10.0.0.6','10.0.0.7','10.0.0.8','10.0.0.9','10.0.0.10']
REAL_MAC_OF_INTERNAL_HOST=["0:0:0:0:0:1","0:0:0:0:0:2","0:0:0:0:0:3","0:0:0:0:0:4","0:0:0:0:0:5","0:0:0:0:0:6","0:0:0:0:0:7","0:0:0:0:0:8","0:0:0:0:0:9","0:0:0:0:0:10"]                                   
IP_OF_DNS_SERVER = '10.0.0.11'
MAC_OF_DNS_SERVER = '00:00:00:00:00:01'


class Entry (object):
  """
  We use the port to determine which port to forward traffic out of.
  We use the MAC to answer ARP replies.
  We use the timeout so that if an entry is older than ARP_TIMEOUT, we
   flood the ARP request rather than try to answer it ourselves.
  """
  def __init__ (self, port, mac):
    self.timeout = time.time() + ARP_TIMEOUT
    self.port = port
    self.mac = mac

  def __eq__ (self, other):
    if type(other) == tuple:
      return (self.port,self.mac)==other
    else:
      return (self.port,self.mac)==(other.port,other.mac)
  def __ne__ (self, other):
    return not self.__eq__(other)
	
  def isExpired (self):
    if self.port == of.OFPP_NONE: return False
    return time.time() > self.timeout


def dpid_to_mac (dpid):
  return EthAddr("%012x" % (dpid & 0xffFFffFFffFF,))

class Test(threading.Thread):
  def __init__(self,time):
    threading.Thread.__init__(self)
    self._run_time=time

  def run(self):
    global mutex
    global v_ip
    for i in range(10):
      mutex.acquire()
      v_ip=_update_ip(128,248,10)
      mutex.release()
      time.sleep(self._run_time)
      

#This is new added.
def _handle_ConnectionUp(event):
  global s1_dpid,s2_dpid,s3_dpid,s4_dpid,s5_dpid,s6_dpid,s7_dpid,s8_dpid,s9_dpid,s10_dpid
  print "ConnectionUp:",dpidToStr(event.connection.dpid)
  
#remember the connection dpid for switch
  for m in event.connection.features.ports:
    if m.name=="s1-eth1":
      s1_dpid=event.connection.dpid
      log.info("s1_dpid=%i",s1_dpid)
    elif m.name=="s2-eth1":
      s2_dpid=event.connection.dpid
      log.info("s2_dpid=%i",s2_dpid)
    elif m.name=="s3-eth1":
      s3_dpid=event.connection.dpid
      log.info("s3_dpid=%i",s3_dpid)
    elif m.name=="s4-eth1":
      s4_dpid=event.connection.dpid
      log.info("s4_dpid=%i",s4_dpid)
    elif m.name=="s5-eth1":
      s5_dpid=event.connection.dpid
      log.info("s5_dpid=%i",s5_dpid)
    elif m.name=="s6-eth1":
      s6_dpid=event.connection.dpid
      log.info("s6_dpid=%i",s6_dpid)
    elif m.name=="s7-eth1":
      s7_dpid=event.connection.dpid
      log.info("s7_dpid=%i",s7_dpid)
    elif m.name=="s8-eth1":
      s8_dpid=event.connection.dpid
      log.info("s8_dpid=%i",s8_dpid)
    elif m.name=="s9-eth1":
      s9_dpid=event.connection.dpid
      log.info("s9_dpid=%i",s9_dpid)
    elif m.name=="s10-eth1":
      s10_dpid=event.connection.dpid
      log.info("s10_dpid=%i",s10_dpid)

def _update_ip(vip_start,vip_end,host_num):
  inter=[vip_start+i*(vip_end-vip_start)/host_num for i in range(host_num+1)]
  vip=[]
  for i in range(host_num):
      n=random.randint(inter[i],inter[i+1])
      ip="10.0.0."+str(n)
      vip.append(ip)
      log.info("h%i's virtual ip is %s.",i+1,ip)
  return vip

def _choose_vip(rip,vip):
  rip=str(rip)
  ripv=rip.split('.')
  ipv=int(ripv[3])
  return vip[ipv-1]

def _forwarding_start(dpid,ipv,out_port,event,v_ip,dstip):
  msg=of.ofp_flow_mod()
  msg.priority=100
  msg.idle_timeout=0
  msg.hard_timeout=0
  msg.match.dl_type=0x0800
  msg.actions.append(of.ofp_action_nw_addr.set_dst(_choose_vip(dstip,v_ip)))
  msg.match.nw_dst=_choose_vip(dstip,v_ip)
  log.info("the real ip is %s and it's vip is %s",dstip,_choose_vip(dstip,v_ip))
  msg.actions.append(of.ofp_action_output(port=out_port[dpid-1][ipv-1]))
  event.connection.send(msg)

def _forwarding(dpid,ipv,out_port,vip_rip_map,event,dstip):
  msg=of.ofp_flow_mod()
  msg.priority=100
  msg.idle_timeout=0
  msg.hard_timeout=0
  msg.match.dl_type=0x0800
  #log.info("the real ip is %s and it's vip is %s",vip_rip_map[str(dstip)],dstip)
  msg.match.nw_dst=dstip
  msg.actions.append(of.ofp_action_output(port=out_port[dpid-1][ipv-1]))
  event.connection.send(msg)

def _forwarding_end(dst_rip,event):
  msg=of.ofp_flow_mod()
  msg.priority=100
  msg.idle_timeout=0
  msg.hard_timeout=0
  msg.match.dl_type=0x0800
  msg.match.nw_dst=dst_rip
  msg.actions.append(of.ofp_action_output(port=1))
  event.connection.send(msg)

def _mut_forward(dpid,dstip,srcip,event,out_port,v_ip,vip_rip_map):

  if dstip in REAL_IP_OF_INTERNAL_HOST:
    dstip=str(dstip)
    dstipv=dstip.split('.')
    ipv=int(dstipv[3])
    msg=of.ofp_packet_out(data=event.ofp)
    msg.actions.append(of.ofp_action_nw_addr.set_dst(_choose_vip(dstip,v_ip)))
    msg.actions.append(of.ofp_action_nw_addr.set_src(_choose_vip(srcip,v_ip)))
    log.info("the dstip is %s and the srcip is %s", _choose_vip(dstip,v_ip),_choose_vip(srcip,v_ip))
    msg.actions.append(of.ofp_action_output(port=out_port[dpid-1][ipv-1]))
    event.connection.send(msg)
    _forwarding_start(dpid,ipv,out_port,event,v_ip,dstip)

  if dstip not in REAL_IP_OF_INTERNAL_HOST:

    rip=vip_rip_map[str(dstip)]
    rip=str(rip)
    ripv=rip.split('.')
    ipv=int(ripv[3])
    if out_port[dpid-1][ipv-1]==1:
      msg=of.ofp_packet_out(data=event.ofp)
      msg.actions.append(of.ofp_action_nw_addr.set_dst(vip_rip_map[str(dstip)]))
      log.info("dst vip %s => dst rip %s",dstip,vip_rip_map[str(dstip)])
      #msg.actions.append(of.ofp_action_nw_addr.set_src(vip_rip_map[str(srcip)]))
      #log.info("src vip %s => src rip %s",srcip,vip_rip_map[str(srcip)])
      msg.actions.append(of.ofp_action_output(port=1))
      event.connection.send(msg)
      _forwarding_end(vip_rip_map[str(dstip)],event)

    if out_port[dpid-1][ipv-1]!=1:
      msg=of.ofp_packet_out(data=event.ofp)
      log.info("routing ! the dstip is %s",dstip)
      msg.actions.append(of.ofp_action_output(port=out_port[dpid-1][ipv-1]))
      event.connection.send(msg)
      _forwarding(dpid,ipv,out_port,vip_rip_map,event,dstip)

def _arp_output(dpid,dstip,event,out_port):
  dstip=str(dstip)
  dstipv=dstip.split('.')
  ipv=int(dstipv[3])
  msg=of.ofp_packet_out(data=event.ofp)
  msg.actions.append(of.ofp_action_output(port=out_port[dpid-1][ipv-1]))
  event.connection.send(msg)

class l3_switch (EventMixin):
  def __init__ (self, fakeways = [], arp_for_unknowns = False):
    # These are "fake gateways" -- we'll answer ARPs for them with MAC
    # of the switch they're connected to.
    self.fakeways = set(fakeways)

    # If this is true and we see a packet for an unknown
    # host, we'll ARP for it.
    self.arp_for_unknowns = arp_for_unknowns

    # (IP,dpid) -> expire_time
    # We use this to keep from spamming ARPs
    self.outstanding_arps = {}

    # (IP,dpid) -> [(expire_time,buffer_id,in_port), ...]
    # These are buffers we've gotten at this datapath for this IP which
    # we can't deliver because we don't know where they go.
    self.lost_buffers = {}

    # For each switch, we map IP addresses to Entries
    self.arpTable = {}

    # This timer handles expiring stuff
    self._expire_timer = Timer(5, self._handle_expiration, recurring=True)

    self.listenTo(core)

    # initialize virtual ip pool
    self.vipList = []
    self.v_ip=[]
    self.v_ip=_update_ip(128,248,10)
    n=10
    num=(248-128)/n
    a=128
    b=248
    inter=[a+i*(b-a)/n for i in range(n+1)]
    for i in range(n):
      self.vipList.append(["10.0.0.%s"%i for i in range(inter[i],inter[i+1])])

    self.srcip_dstvip_map = {}
    self.rip_vip_map={}
    self.vip_rip_map={}
    for i in range(n):
        for j in range(len(self.vipList[i])):
            self.vip_rip_map[self.vipList[i][j]]=REAL_IP_OF_INTERNAL_HOST[i]
    self.vip_rip_map["10.0.0.248"]=REAL_IP_OF_INTERNAL_HOST[9]

    #install the decision of packet forwarding from which port
    self.out_port=[]
    self.out_port=[[1,4,5,4,5,6,3,2,6,6],
              [2,1,2,4,5,4,3,2,4,5],
              [3,3,1,5,4,4,3,2,5,4],
              [2,2,4,1,3,3,2,4,5,3],
              [2,4,2,3,1,3,4,2,3,5],
              [4,3,2,3,2,1,4,4,6,5],
              [2,3,2,3,3,2,1,2,3,2],
              [2,2,3,3,3,2,2,1,2,3],
              [3,2,2,2,3,3,2,3,1,3],
              [3,2,2,3,2,3,3,2,3,1]]

            
  def _handle_expiration (self):
    # Called by a timer so that we can remove old items.
    empty = []
    for k,v in self.lost_buffers.iteritems():
      ip,dpid = k
      expires_at,buffer_id,in_port = v

      for item in list(v):
        if expires_at < time.time():
          # This packet is old.  Tell this switch to drop it.
          v.remove(item)
          po = of.ofp_packet_out(buffer_id = buffer_id, in_port = in_port)
          core.openflow.sendToDPID(dpid, po)
      if len(v) == 0: empty.append(k)

    # Remove empty buffer bins
    for k in empty:
      del self.lost_buffers[k]

  def _send_lost_buffers (self, dpid, ipaddr, macaddr, port):
    """
    We may have "lost" buffers -- packets we got but didn't know
    where to send at the time.  We may know now.  Try and see.
    """
    if (dpid,ipaddr) in self.lost_buffers:
      # Yup!
      bucket = self.lost_buffers[(dpid,ipaddr)]
      del self.lost_buffers[(dpid,ipaddr)]
      log.debug("Sending %i buffered packets to %s from %s"
                % (len(bucket),ipaddr,dpidToStr(dpid)))
      for _,buffer_id,in_port in bucket:
        po = of.ofp_packet_out(buffer_id=buffer_id,in_port=in_port)
        po.actions.append(of.ofp_action_dl_addr.set_dst(macaddr))
        po.actions.append(of.ofp_action_output(port = port))
        core.openflow.sendToDPID(dpid, po)


  def _handle_GoingUpEvent (self, event):
    self.listenTo(core.openflow)
    log.debug("Up...")

  def _handle_PacketIn (self, event):
    dpid = event.connection.dpid

    inport = event.port
    packet = copy.deepcopy(event.parsed)
    if not packet.parsed:
      log.warning("%i %i ignoring unparsed packet", dpid, inport)
      return

    if dpid not in self.arpTable:
      # New switch -- create an empty table
      self.arpTable[dpid] = {}
      for fake in self.fakeways:
        self.arpTable[dpid][IPAddr(fake)] = Entry(of.OFPP_NONE,
         dpid_to_mac(dpid))

    # store the mac, ip info of the DNS SERVER into arpTable
    self.arpTable[dpid][IPAddr(IP_OF_DNS_SERVER)]=Entry(6633, EthAddr(MAC_OF_DNS_SERVER))

    if packet.type == ethernet.LLDP_TYPE:
      # Ignore LLDP packets
      return

    global s1_dpid,s2_dpid,s3_dpid,s4_dpid,s5_dpid,s6_dpid,s7_dpid,s8_dpid,s9_dpid,s10_dpid
    global v_ip
    if v_ip is None:
      v_ip=self.v_ip
    packet=event.parsed

    ap=packet.find('arp')
    icm=packet.find('icmp')


    if ap:
      #_arp_output(event.connection.dpid,ap.protodst,event,self.out_port)
      _mut_forward(event.connection.dpid,ap.protodst,ap.protosrc,event,self.out_port,v_ip,self.vip_rip_map)

    if isinstance(packet.next,ipv4):
      _mut_forward(event.connection.dpid,packet.next.dstip,packet.next.srcip,event,self.out_port,v_ip,self.vip_rip_map)
        


def launch (fakeways="", arp_for_unknowns=None):
  fakeways = fakeways.replace(","," ").split()
  fakeways = [IPAddr(x) for x in fakeways]
  if arp_for_unknowns is None:
    arp_for_unknowns = len(fakeways) > 0
  else:
    arp_for_unknowns = str_to_bool(arp_for_unknowns)
  core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
  core.registerNew(l3_switch, fakeways, arp_for_unknowns)
  global mutex
  mutex=threading.Lock()
  t1=Test(10)
  t1.start()
