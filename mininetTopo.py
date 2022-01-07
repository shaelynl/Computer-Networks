'''
Please add your name: SHAELYN LAM
Please add your matric number: A0203271W
'''

import os
import sys
import atexit
import argparse
from mininet.net import Mininet
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.topo import Topo
from mininet.link import Link
from mininet.node import RemoteController

net = None

MEGA_BITS = 1000000
DEFAULT_RATIO = 0.5
PREMIUM_RATIO = 0.8

qosCommands = []

def run_qos():
    for cmd in qosCommands:
        os.system(cmd)

class TreeTopo(Topo):

    def __init__(self):
		# Initialize topology
        Topo.__init__(self)

        mapNodes = {}

        qosHostConfig = ' qos=@newqos \
           -- --id=@newqos create QoS type=linux-htb other-config:max-rate=%s queues=0=@q0,1=@q1 \
           -- --id=@q0 create queue other-config:max-rate=%s \
           -- --id=@q1 create queue other-config:min-rate=%s other-config:max-rate=%s'

        qosSwitchConfig = ' qos=@newqos -- --id=@newqos create QoS type=linux-htb other-config:max-rate=%s'

        with open('topology.in', 'r') as f:
            index = 1
            for line in f:
                line = line.strip("\n ' '")
                if index == 1:
                    firstLine = line.split(' ')
                    numHost = int(firstLine[0])
                    numSwitch = int(firstLine[1])
                    numLink = int(firstLine[2])

                    for hIndex in range(1, numHost + 1):
                        hostId = 'h%d' % hIndex
                        hostObj = self.addHost(hostId)
                        mapNodes[hostId] = hostObj

                        cmd = 'h{0}.setIP("10.0.0.{0}/24")'.format(hIndex)
                        os.system(cmd)

                    for sIndex in range(1, numSwitch + 1):
                        switchId = 's%d' % sIndex
                        sconfig = {'dpid': "%016x" % sIndex}
                        switchObj = self.addSwitch(switchId, **sconfig)
                        mapNodes[switchId] = switchObj

                else:
                    # link rows
                    items = line.split(',')
                    firstNode = items[0]
                    secondNode = items[1]
                    bandwidth = int(items[2])

                    # print "Read %s <---> %s on %s" % (firstNode, secondNode, bandwidth)
                    link = self.addLink(mapNodes[firstNode], mapNodes[secondNode])
                    print "Link...interface = %s" % (self.linkInfo(firstNode, secondNode))

                    # Create QoS for each link
                    info = self.linkInfo(firstNode, secondNode)
                    maxBandwidth = str(bandwidth * MEGA_BITS)
                    defaultMaxBandwidth = str(bandwidth * MEGA_BITS * DEFAULT_RATIO)
                    premiumMinBandwidth = str(bandwidth * MEGA_BITS * PREMIUM_RATIO)

                    firstPort = str('%s-eth%s' % (firstNode, str(info["port1"])))
                    secondPort = str('%s-eth%s' % (secondNode, str(info["port2"])))

                    if ('s' in firstNode and 's' in secondNode):
                        print "same"
                    else:
                        cmd = 'sudo ovs-vsctl -- set Port %s ' + qosHostConfig
                        if ('s' in firstNode):
                            cmd = cmd % (firstPort, maxBandwidth, defaultMaxBandwidth, premiumMinBandwidth, maxBandwidth)
                        else:
                            cmd = cmd % (secondPort, maxBandwidth, defaultMaxBandwidth, premiumMinBandwidth, maxBandwidth)
                        qosCommands.append(cmd)
                index +=1

def startNetwork():

    info('** Creating the tree network\n')
    topo = TreeTopo()

    global net
    net = Mininet(topo=topo, link = Link,
                  controller=lambda name: RemoteController(name, ip='127.0.0.1'),
                  listenPort=6633, autoSetMacs=True)

    info('** Starting the network\n')
    net.start()

    run_qos()

    info('** Running CLI\n')
    CLI(net)

def stopNetwork():
    if net is not None:
        net.stop()
        # Remove QoS and Queues
        os.system('sudo ovs-vsctl --all destroy Qos')
        os.system('sudo ovs-vsctl --all destroy Queue')


if __name__ == '__main__':
    # Force cleanup on exit by registering a cleanup function
    atexit.register(stopNetwork)

    # Tell mininet to print useful information
    setLogLevel('info')
    startNetwork()
