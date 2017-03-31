from mininet.topo import Topo
from mininet.net import Mininet

from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.cli import CLI

from mininet.node import *

import os

class createMyTopo(Topo):
    "Experiment-use topology."

    def __init__(self):
        "Create custom topo."

        # Initialize topology
        Topo.__init__(self)

        #Add hosts and switches
        h1=self.addHost('h1')
        h2=self.addHost('h2')
        h3=self.addHost('h3')
        h4=self.addHost('h4')
        h5=self.addHost('h5')
        h6=self.addHost('h6')
        h7=self.addHost('h7')
        h8=self.addHost('h8')
        h9=self.addHost('h9')
        h10=self.addHost('h10')
        s1=self.addSwitch('s1')
        s2=self.addSwitch('s2')
        s3=self.addSwitch('s3')
        s4=self.addSwitch('s4')
        s5=self.addSwitch('s5')
        s6=self.addSwitch('s6')
        s7=self.addSwitch('s7')
        s8=self.addSwitch('s8')
        s9=self.addSwitch('s9')
        s10=self.addSwitch('s10')

        #Add links
        self.addLink(s1,h1)
        self.addLink(s2,h2)
        self.addLink(s3,h3)
        self.addLink(s4,h4)
        self.addLink(s5,h5)
        self.addLink(s6,h6)
        self.addLink(s7,h7)
        self.addLink(s8,h8)
        self.addLink(s9,h9)
        self.addLink(s10,h10)
        self.addLink(s1,s8)
        self.addLink(s1,s7)
        self.addLink(s1,s2)
        self.addLink(s2,s7)
        self.addLink(s3,s8)
        self.addLink(s1,s3)
        self.addLink(s3,s5)
        self.addLink(s2,s4)
        self.addLink(s5,s6)
        self.addLink(s4,s6)
        self.addLink(s3,s4)
        self.addLink(s2,s5)
        self.addLink(s1,s6)
        self.addLink(s5,s10)
        self.addLink(s6,s10)
        self.addLink(s4,s9)
        self.addLink(s6,s9)

def perfTest():
    "Create network and run simple performance test"
    topo=createMyTopo()
    net=Mininet(topo=topo,host=CPULimitedHost,link=TCLink,controller=RemoteController)
    net.start()
    print "Dumping host connections"
    dumpNodeConnections(net.hosts)
    h1,h2,h3,h4,h5=net.get('h1','h2','h3','h4','h5')
    h6,h7,h8,h9,h10=net.get('h6','h7','h8','h9','h10')
    h1.setMAC("0:0:0:0:0:1")
    h2.setMAC("0:0:0:0:0:2")
    h3.setMAC("0:0:0:0:0:3")
    h4.setMAC("0:0:0:0:0:4")
    h5.setMAC("0:0:0:0:0:5")
    h6.setMAC("0:0:0:0:0:6")
    h7.setMAC("0:0:0:0:0:7")
    h8.setMAC("0:0:0:0:0:8")
    h9.setMAC("0:0:0:0:0:9")
    h10.setMAC("0:0:0:0:0:10")
    h1.setIP("10.0.0.1")
    h2.setIP("10.0.0.2")
    h3.setIP("10.0.0.3")
    h4.setIP("10.0.0.4")
    h5.setIP("10.0.0.5")
    h6.setIP("10.0.0.6")
    h7.setIP("10.0.0.7")
    h8.setIP("10.0.0.8")
    h9.setIP("10.0.0.9")
    h10.setIP("10.0.0.10")
    CLI(net)
    net.stop()

if __name__=='__main__':
    setLogLevel('info')
    perfTest()
