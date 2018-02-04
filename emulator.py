#! /usr/bin/env python
# -*- coding:utf-8 -*-

# from emulator import VirtualHost
from scapy.all import *
import pprint
import threading
import time
import copy
import csv
import sys
import re

def logger(level, module, message):
    print "[" + level + "][" + module + "]" + message
class queue(threading.Thread):
    def __init__(self, nic):
        threading.Thread.__init__(self)
        self.nic = nic
        self.list = []
        self.stopFlag = True
    def add(self, packet):
        self.list.append(packet)
    def run(self):
        self.stopFlag = False
        while True:
            if self.stopFlag :
                break
            if len(self.list)>0 :
                packet = self.list.pop(0)
                self.nic.dispatch(packet)
            else:
                time.sleep(0.1)
    def stop(self):
        self.stopFlag = True

class nic(threading.Thread):
    def __init__(self, nicName):
        threading.Thread.__init__(self)
        self.macAddressTable = {}
        self.nicName = nicName
        self.queue = queue(nic=self)
        self.stopFlag = True
    def getNicName(self):
        return self.nicName
    def addHost(self, mac, host):
        self.macAddressTable[mac] = host
    def sendp(self, packet):
        sendp(packet, iface=self.nicName)
        # mock
        # be careful for call stack depth
        # self.dispatch(packet)
    def run(self):
        self.queue.start()
        self.stopFlag = False
        # TODO
        while True:
            if self.stopFlag:
                break
            reply = sniff(count=2, iface=self.nicName, timeout=5)
            print "recv"
            if reply is not None:
                reply.show()
                for r in reply:
                    self.queue.add(r)
        self.queue.stop()
        self.queue.join()
    def dispatch(self, reply):
        if not reply.haslayer(Ether) :
            return
        if self.macAddressTable.has_key(reply[Ether].src):
            return
        if reply[Ether].dst == "ff:ff:ff:ff:ff:ff":
            for mac in self.macAddressTable:
                self.macAddressTable[mac].recv(reply)
        if self.macAddressTable.has_key(reply[Ether].dst):
            self.macAddressTable[reply[Ether].dst].recv(reply)
        else:
            print "ERROR : cannot dispatch"
            reply.show()
    def stop(self):
        self.stopFlag = True

class VirtualHost(threading.Thread):
    """emulate host behavior"""

    def __init__(self, config, nic, name):
        threading.Thread.__init__(self)
        self.config = copy.deepcopy(config)
        self.ip = self.config["host"]["ip"]
        if self.config["host"]["connect"] == "direct":
            self.mac = self.config["host"]["mac"]
        else:
            self.mac = self.config["host"]["router_mac"]

        self.nic = nic
        self.nic.addHost(mac=self.mac, host=self)
        self.name = name
        self.state = "tcp-closed"
        self.arp_cache = {}


    def run(self):
        return

    def getResult(self):
        return self.result

    def printSettings(self):
        print "*** [" + self.name + "] settings ***"
        print self.ip
        print self.mac
        print self.nic.getNicName()
        print self.config
        print "*** end ***"

    def recv(self, reply):
        # do not use blocking functions
        logger("DEBUG", self.name, "recv packet")

        # ARP
        if reply.haslayer(ARP):
            if reply[ARP].op == ARP.is_at:
                logger("DEBUG", self.name, "recv arp is_at " + reply[ARP].psrc + " " + reply[ARP].hwsrc)
                self.arp_cache[reply[ARP].psrc] = reply[ARP].hwsrc
                return 1
            elif reply[ARP].op == ARP.who_has and reply[ARP].pdst == self.ip:
                logger("DEBUG", self.name, "recv arp who_has " + reply[ARP].pdst + ", send is_at " + self.mac)
                packet = Ether(src=self.mac, dst=reply[ARP].hwsrc)/ARP(op=ARP.is_at, psrc=self.ip, pdst=reply[ARP].psrc, hwsrc=self.mac, hwdst=reply[ARP].hwsrc)
                self.nic.sendp(packet)
                return 1
            return 1 # TODO

        # ICMP
        if(reply[IP].proto == 1 and \
               reply[ICMP].type == 8):
            logger("DEBUG", self.name, "recv icmp-request, send reply")
            packet = Ether(src=reply[Ether].dst, dst=reply[Ether].src)/IP(src=reply[IP].dst, dst=reply[IP].src, len=reply[IP].len)/ICMP(type="echo-reply", id=reply[ICMP].id, seq=reply[ICMP].seq)/Padding(load=reply[Raw].load)
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

        # TODO timeout
        time.sleep(1.0)
        if self.state == "tcp-established":
            logger("DEBUG", self.name, "send test payload");
            packet = Ether(src=self.mac, dst=self.config["FW"]["mac"])/IP(src=self.ip, dst=self.config["scenario"]["dst_ip"])/TCP(sport=self.config["scenario"]["src_port"],dport=self.config["scenario"]["dst_port"],flags="")/"This is a test"
            self.nic.sendp(packet)

            time.sleep(1.0)
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
        # FW mac
        try_count = 0
        while True:
            if not self.config["FW"].has_key("mac") or self.config["FW"]["mac"] == "":
                logger("DEBUG", self.name, "ARP resolv " + self.config["FW"]["ip"])
                packet = Ether(src=self.mac, dst="ff:ff:ff:ff:ff:ff")/ARP(op=ARP.who_has, psrc=self.ip, pdst=self.config["FW"]["ip"], hwsrc=self.mac, hwdst="00:00:00:00:00:00")
                self.nic.sendp(packet)
                try_count += 1
                time.sleep(0.5)
                if self.arp_cache.has_key(self.config["FW"]["ip"]):
                    self.config["FW"]["mac"] = self.arp_cache[self.config["FW"]["ip"]]
                    logger("DEBUG", self.name, "ARP resolv " + self.config["FW"]["ip"] + " is " + self.config["FW"]["mac"])
                    break
            else:
                break
            if try_count > 5:
                logger("ERROR", self.name, "cannot ARP resolv " + self.config["FW"]["ip"])
                break

        self.icmpTest()
        # self.tcpTest()
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
            self.result = "get icmp-reply"

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

    param = sys.argv
    configReader = csv.reader(open(param[1], 'rb'), delimiter=',', quotechar='"')
    for row in configReader:
        if re.match("^#",row[0]):
            continue
        serverConfig = {}
        serverConfig["host"] = {}
        serverConfig["host"]["connect"] = row[0]
        serverConfig["host"]["ip"] = row[1]
        serverConfig["host"]["interface"] = row[2]
        if row[0] == "direct":
            serverConfig["host"]["mac"] = row[3]
        else:
            serverConfig["host"]["router_mac"] = row[3]
        serverConfig["scenario"] = {}
        serverConfig["scenario"]["type"] = "server"
        serverConfig["scenario"]["protocol"] = row[4]
        serverConfig["scenario"]["listen_port"] = int(row[5])
        serverConfig["FW"] = {}
        serverConfig["FW"]["ip"] = row[6]
        serverConfig["FW"]["mac"] = row[7]
        serverConfig["test"] = {}
        serverConfig["test"]["timeout"] = row[15]

        clientConfig = {}
        clientConfig["host"] = {}
        clientConfig["host"]["connect"] = row[8]
        clientConfig["host"]["ip"] = row[9]
        clientConfig["host"]["interface"] = row[10]
        if row[0] == "direct":
            clientConfig["host"]["mac"] = row[11]
        else:
            clientConfig["host"]["router_mac"] = row[11]
        clientConfig["scenario"] = {}
        clientConfig["scenario"]["type"] = "client"
        clientConfig["scenario"]["protocol"] = row[4]
        clientConfig["scenario"]["dst_ip"] = row[1]
        clientConfig["scenario"]["dst_port"] = int(row[5])
        clientConfig["scenario"]["src_port"] = int(row[12])
        clientConfig["FW"] = {}
        clientConfig["FW"]["ip"] = row[13]
        clientConfig["FW"]["mac"] = row[14]
        clientConfig["test"] = {}
        clientConfig["test"]["timeout"] = row[15]

    # TODO check config dictionary before

    # server
    config = serverConfig
    testNic = nic(nicName=config["host"]["interface"])
    testNic.start()
    if config["scenario"]["type"] == "server":
        testServer = VirtualServer( \
            config=config, \
                nic=testNic, \
                name="testServer");
        testServer.printSettings();
        testServer.start()

    time.sleep(0.5)

    # client
    config = clientConfig

    if config["scenario"]["type"] == "client":
        testClient = VirtualClient( \
            config=config, \
                nic=testNic, \
                name="testClient");
        testClient.printSettings()
        testClient.run()

    time.sleep(1.0)

    time.sleep(2.0)
    testNic.stop()
    testNic.join()

    print testClient.getResult()

