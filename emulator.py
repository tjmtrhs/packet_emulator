#! /usr/bin/env python
# -*- coding:utf-8 -*-

# from emulator import VirtualHost
from scapy.all import *
import pprint
import threading
import time
import copy

def logger(level, module, message):
    print "[" + level + "][" + module + "]" + message

class nic(threading.Thread):
    def __init__(self, nicName):
        threading.Thread.__init__(self)
        self.macAddressTable = {}
        self.nicName = nicName
    def getNicName(self):
        return self.nicName
    def addHost(self, mac, host):
        self.macAddressTable[mac] = host
    def sendp(self, packet):
        # sendp(packet, iface=self.nicName)
        # mock
        # be careful for call stack depth
        self.dispatch(packet)
    def run(self):
        # TODO
        while True:
            reply = srp1(self.dummyPacket, iface=self.nicName)
            self.dispatch(reply)
    def dispatch(self, reply):
        if self.macAddressTable.has_key(reply[Ether].dst):
            self.macAddressTable[reply[Ether].dst].recv(reply)
        else:
            print "ERROR : cannot dispatch"
            reply.show()

class VirtualHost(threading.Thread):
    """emulate host behavior"""

    def __init__(self, config, nic, name):
        threading.Thread.__init__(self)
        self.config = copy.deepcopy(config)
        self.ip = config["host"]["ip"]
        self.mac = config["host"]["mac"] if config["host"]["connect"] == "direct" else config["host"]["router_mac"]

        self.nic = nic
        self.nic.addHost(mac=self.mac, host=self)
        self.name = name
        self.state = "tcp-closed"


    def run(self):
        return

    def getResult(self):
        return self.result

    def printSettings(self):
        print "*** [" + self.name + "] settings ***"
        print self.ip
        print self.mac
        print self.nic.getNicName()
        print "*** end ***"

    def recv(self, reply):
        # do not use blocking functions
        logger("DEBUG", self.name, "recv packet")

        # ICMP
        if(reply[IP].proto == 1 and \
               reply[ICMP].type == 8):
            logger("DEBUG", self.name, "recv icmp-request, send reply")
            packet = Ether(src=reply[Ether].dst, dst=reply[Ether].src)/IP(src=reply[IP].dst, dst=reply[IP].src)/ICMP(type="echo-reply")
            self.nic.sendp(packet)

        # TCP negotiation
        if(self.state == "tcp-syn_sent" and \
               reply[IP].proto == 6 and \
               reply[TCP].flags & (0x02 | 0x10) == (0x02 | 0x10)):
            # 実はACKは無くてもいいかもしれない
            logger("DEBUG", self.name, "recv SYN ACK, change state to established, send ACK")
            packet = Ether(src=reply[Ether].dst, dst=reply[Ether].src)/IP(src=reply[IP].dst, dst=reply[IP].src)/TCP(sport=reply[TCP].dport, dport=reply[TCP].sport, flags="A")
            self.state = "tcp-established"
            self.nic.sendp(packet)
        elif(self.state == "tcp-listen" and \
                 reply[IP].proto == 6 and \
                 reply[TCP].flags & 0x02 == 0x02):
            logger("DEBUG", self.name, "recv SYN, change state to syn_rcvd, send SYN ACK")
            packet = Ether(src=reply[Ether].dst, dst=reply[Ether].src)/IP(src=reply[IP].dst, dst=reply[IP].src)/TCP(sport=reply[TCP].dport, dport=reply[TCP].sport, flags="SA")
            self.state = "tcp-syn_rcvd"
            self.nic.sendp(packet)
        elif(self.state == "tcp-syn_rcvd" and \
                 reply[IP].proto == 6 and \
                 reply[TCP].flags & 0x10 == 0x10):
            logger("DEBUG", self.name, "recv ACK, change state to established")
            self.state = "tcp-established"
        elif(self.state == "tcp-established" and \
                 reply[IP].proto == 6 and \
                 reply[TCP].flags & 0x01 == 0x01):
            logger("DEBUG", self.name, "recv FIN, change state to close_wait, send ACK")
            self.state = "tcp-close_wait"
            packet = Ether(src=reply[Ether].dst, dst=reply[Ether].src)/IP(src=reply[IP].dst, dst=reply[IP].src)/TCP(sport=reply[TCP].dport, dport=reply[TCP].sport, flags="A")
            self.nic.sendp(packet)
            logger("DEBUG", self.name, "change state to last_ack, send FIN")
            self.state = "tcp-last_ack"
            packet = Ether(src=reply[Ether].dst, dst=reply[Ether].src)/IP(src=reply[IP].dst, dst=reply[IP].src)/TCP(sport=reply[TCP].dport, dport=reply[TCP].sport, flags="F")
            self.nic.sendp(packet)
        elif(self.state == "tcp-last_ack" and \
                 reply[IP].proto == 6 and \
                 reply[TCP].flags & 0x10 == 0x10):
            logger("DEBUG", self.name, "recv ACK, change state to closed")
            self.state = "tcp-closed"
        elif(self.state == "tcp-fin_wait_1" and \
                 reply[IP].proto == 6 and \
                 reply[TCP].flags & 0x01 == 0x01):
            logger("DEBUG", self.name, "recv FIN, change state to closing, send ACK")
            self.state = "tcp-closing"
            packet = Ether(src=reply[Ether].dst, dst=reply[Ether].src)/IP(src=reply[IP].dst, dst=reply[IP].src)/TCP(sport=reply[TCP].dport, dport=reply[TCP].sport, flags="A")
            self.nic.sendp(packet)
        elif(self.state == "tcp-fin_wait_1" and \
                 reply[IP].proto == 6 and \
                 reply[TCP].flags & 0x10 == 0x10):
            logger("DEBUG", self.name, "recv ACK, change state to fin_wait_2")
            self.state = "tcp-fin_wait_2"
        elif(self.state == "tcp-fin_wait_2" and \
                 reply[IP].proto == 6 and \
                 reply[TCP].flags & 0x01 == 0x01):
            logger("DEBUG", self.name, "recv FIN, change state to time_wait, send ACK")
            self.state = "tcp-time_wait"
            packet = Ether(src=reply[Ether].dst, dst=reply[Ether].src)/IP(src=reply[IP].dst, dst=reply[IP].src)/TCP(sport=reply[TCP].dport, dport=reply[TCP].sport, flags="A")
            self.nic.sendp(packet)
        elif(self.state == "tcp-closing" and \
                 reply[IP].proto == 6 and \
                 reply[TCP].flags & 0x10 == 0x10):
            logger("DEBUG", self.name, "recv ACK, change state to time_wait")
            self.state = "tcp-time_wait"


        else:
            return 0
        return 1


class VirtualClient(VirtualHost):
    def __init__(self, config, nic, name):
        # if in python 3, we can write super().__init__(ip)
        super(VirtualClient, self).__init__(config, nic, name)

    def tcpTest(self):
        packet = Ether(src=self.mac, dst=self.config["FW"]["mac"])/IP(src=self.ip, dst=self.config["scenario"]["dst_ip"])/TCP(sport=self.config["scenario"]["src_port"],dport=self.config["scenario"]["dst_port"],flags="S")

        logger("DEBUG", self.name, "send SYN, change state to syn_sent")
        self.state = "tcp-syn_sent"
        self.nic.sendp(packet)

        if self.state == "tcp-established":
            logger("DEBUG", self.name, "send test payload");
            packet = Ether(src=self.mac, dst=self.config["FW"]["mac"])/IP(src=self.ip, dst=self.config["scenario"]["dst_ip"])/TCP(sport=self.config["scenario"]["src_port"],dport=self.config["scenario"]["dst_port"],flags="")/"This is a test"
            self.nic.sendp(packet)

            # close connection
            logger("DEBUG", self.name, "send FIN, change state to FIN_WAIT_1");
            self.state = "tcp-fin_wait_1"
            packet = Ether(src=self.mac, dst=self.config["FW"]["mac"])/IP(src=self.ip, dst=self.config["scenario"]["dst_ip"])/TCP(sport=self.config["scenario"]["src_port"],dport=self.config["scenario"]["dst_port"],flags="F")
            self.nic.sendp(packet)
        return

    def icmpTest(self):
        packet = Ether(src=self.mac, dst=self.config["FW"]["mac"])/IP(src=self.ip, dst=self.config["scenario"]["dst_ip"])/ICMP(type="echo-request")
        logger("DEBUG", self.name, "send ICMP-request")
        self.nic.sendp(packet)
        return

    def run(self):
        self.icmpTest()
        self.tcpTest()
        return

    def recv(self, reply):
        # do not use blocking functions
        # default behavior
        ret = super(VirtualClient, self).recv(reply)
        if ret == 1:
            return
        if reply[IP].proto == 6 and reply[TCP].flags & 0x10 == 0x10:
            logger("DEBUG", self.name, "recv ACK+msg, send ACK")
            self.result = reply.load
            packet = Ether(src=reply[Ether].dst, dst=reply[Ether].src)/IP(src=reply[IP].dst, dst=reply[IP].src)/TCP(sport=reply[TCP].dport, dport=reply[TCP].sport, flags="A")
            self.nic.sendp(packet)
        if reply[IP].proto == 1 and reply[ICMP].type == 0:
            logger("DEBUG", self.name, "recv icmp-reply")

    def getResult(self):
        return self.result

class VirtualServer(VirtualHost):
    def __init__(self, config, nic, name):
        # if in python 3, we can write super().__init__(ip)
        super(VirtualServer, self).__init__(config, nic, name)

    def run(self):
        self.state = "tcp-listen"
        logger("DEBUG", self.name, "change state to listen")

        return
    def recv(self, reply):
        # do not use blocking functions
        # default behavior
        ret = super(VirtualServer, self).recv(reply)
        if ret == 1:
            return
        # omugaeshi
        if self.state == "tcp-established" and \
                reply[IP].proto == 6 :
            if reply[TCP].flags & 0x10 == 0x10:
                logger("DEBUG", self.name, "recv ACK")
            else:
                logger("DEBUG", self.name, "recv mesage, send ACK+msg")
                self.result = reply.load
                packet = Ether(src=reply[Ether].dst, dst=reply[Ether].src)/IP(src=reply[IP].dst, dst=reply[IP].src)/TCP(sport=reply[TCP].dport, dport=reply[TCP].sport, flags="A")/( "okaeshi" + reply.load)
                self.nic.sendp(packet)


    def getResult(self):
        return self.result

if __name__ == '__main__':

    config = {}

    # server
    config["host"] = {}
    config["host"]["connect"] = "direct" # or "router"
    config["host"]["ip"] = "10.0.0.1"
    config["host"]["interface"] = "lo"
    config["host"]["mac"] = "11:11:11:11:11:11"
    config["scenario"] = {}
    config["scenario"]["type"] = "server" # or "client"
    config["scenario"]["protocol"] = "tcp" # or "udp", "icmp"
    config["scenario"]["listen_port"] = 22 # must be integer
    config["FW"] = {}
    config["FW"]["mac"] = "22:22:22:22:22:22"
    config["test"] = {}
    config["test"]["timeout"] = 30



    # TODO check config dictionary before

    testNic = nic(nicName=config["host"]["interface"])
    if config["scenario"]["type"] == "server":
        testServer = VirtualServer( \
            config=config, \
                nic=testNic, \
                name="testServer");
        testServer.printSettings();
        testServer.start()

    time.sleep(0.5)

    # client
    config["host"] = {}
    config["host"]["connect"] = "router"
    config["host"]["ip"] = "192.168.0.2"
    config["host"]["interface"] = "lo"
    config["host"]["router_mac"] = "22:22:22:22:22:22"
    config["scenario"] = {}
    config["scenario"]["type"] = "client"
    config["scenario"]["protocol"] = "tcp" # or "udp", "icmp"
    config["scenario"]["dst_ip"] = "10.0.0.1"
    config["scenario"]["dst_port"] = 22
    config["scenario"]["src_port"] = 5000
    config["FW"] = {}
    config["FW"]["mac"] = "11:11:11:11:11:11"
    config["test"] = {}
    config["test"]["timeout"] = "30"

    if config["scenario"]["type"] == "client":
        testClient = VirtualClient( \
            config=config, \
                nic=testNic, \
                name="testClient");
        testClient.printSettings()
        testClient.run()

    print testClient.getResult()
    print testServer.getResult()

