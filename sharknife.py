from scapy.all import sniff,TCP,UDP,ICMP,IP,ARP,Dot11Deauth
from time import time,ctime
time = ctime(time())

check = []
ports = [21,22,23.25]

def Detect(packet):
    if packet.haslayer(ICMP):
        print(f"##PING DETECTED## {packet[IP].src} -> {packet[IP].dst} {time}")

    if packet.haslayer(TCP):
        if packet.haslayer(IP):
            if packet[TCP].flags == "S": 
                if packet[IP].src in check and packet[TCP].dport in ports:
                    print(f"##TCP SYN DETECTED## {packet[IP].src}:{packet[TCP].sport} -> {packet[IP].dst}:{packet[TCP].dport} {time}")
                check.append(packet[IP].src)
            elif packet[TCP].flags == "F":
                if packet[IP].src in check and packet[TCP].dport in ports:
                    print(f"##TCP FIN DETECTED## {packet[IP].src}:{packet[TCP].sport} -> {packet[IP].dst}:{packet[TCP].dport} {time}")
                check.append(packet[IP].src)

    if packet.haslayer(UDP):
        if packet.haslayer(IP):
            if packet[IP].src in check and packet[UDP].dport in ports:
                print(f"##UDP DETECTED## {packet[IP].src}:{packet[UDP].sport} -> {packet[IP].dst}:{packet[UDP].dport} {time}")
            check.append(packet[IP].src)

    if packet.haslayer(ARP):
        print(f"##WIFI CONNECTION DETECTED## {packet[ARP].psrc} <-> {packet[ARP].hwsrc} {time}")

    if packet.haslayer(Dot11Deauth):
        print(f"##WIFI DEAUTHTENTICATION DETECTED## {packet[802.11].addr1} {time}")


sniff(prn=Detect, count=0, store=False)
#if __name__ == "__main__":

