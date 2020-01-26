#! /usr/bin/env python

import scapy.all as scapy
import optparse

def print_motd():
    print("""
 _     _ _______ _______ _     _
 |_____| |_____| |______ |_____|
 |     | |     | ______| |     |                               
""")

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t","--target",dest="target_ip",help="Specify the target IP Address to scan the network")
    options = parser.parse_args()[0]

    if not options.target_ip:
        print_motd()
        parser.error("[-]Please specify target IP Address. Type option -h / --help for help")
    else:
        return options

def scan(ip):
    # scapy.arping(ip)
    arp_request = scapy.ARP(pdst=ip)
    # arp_request.show()
    # print(arp_request.summary())
    # scapy.ls(scapy.ARP)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # broadcast.show()
    # scapy.ls(scapy.Ether)
    # print(broadcast.summary())
    arp_request_broadcast = broadcast / arp_request
    # print(arp_request_broadcast.summary())
    # arp_request_broadcast.show()
    answered_list = scapy.srp(arp_request_broadcast, timeout=1,verbose=False)[0]
    print("[+]ARP + Ether Packets Broadcasted Succesffully")
    print("[+]Response Received from Devices")
    #print(answered_list.summary())
    clients_list = []
    for element in answered_list :
        client_dict = {"ip":element[1].psrc,"mac":element[1].hwsrc}
        clients_list.append(client_dict)
        #print(element[1].psrc + "\t\t" + element[1].hwsrc)
    return clients_list


def print_result(result_list):
    print("-----------------------------------------------\nIP\t\t\tMAC Address\n-----------------------------------------------------")
    for client in result_list:
        print(client["ip"]+"\t\t"+client["mac"])

options = get_arguments()
print("[+]Selected IP Range to scan : "+options.target_ip)
scan_result = scan(options.target_ip)
print("[+]Discovered Devices List ")
print_motd()
print_result(scan_result)

