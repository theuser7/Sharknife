from scapy.all import sniff,TCP,UDP,ICMP,IP,ARP,Dot11Deauth
import datetime

check = []
ports = [21,22,23.25]
def Detect(packet):
    time = datetime.datetime.now()
    time = time.strftime("%H:%M:%S")
    if packet.haslayer(ICMP):
        if packet[ICMP].type == 8:
            print(f"##PING EVENT##  SRC# {packet[IP].src} -> DST# {packet[IP].dst} HOUR# {time}")

    if packet.haslayer(TCP):
        if packet.haslayer(IP):
            if packet[TCP].flags == "S": 
                if packet[IP].src in check and packet[TCP].dport in ports:
                    print(f"##TCP SYN EVENT## SRC# {packet[IP].src}:{packet[TCP].sport} -> DST# {packet[IP].dst}:{packet[TCP].dport} HOUR# {time}")
                check.append(packet[IP].src)
            elif packet[TCP].flags == "F":
                if packet[IP].src in check and packet[TCP].dport in ports:
                    print(f"##TCP FIN EVENT## SRC {packet[IP].src}:{packet[TCP].sport} -> DST# {packet[IP].dst}:{packet[TCP].dport} HOUR# {time}")
                check.append(packet[IP].src)

    if packet.haslayer(UDP):
        if packet.haslayer(IP):
            if packet[IP].src in check and packet[UDP].dport in ports:
                print(f"##UDP EVENT## SRC# {packet[IP].src}:{packet[UDP].sport} -> DST# {packet[IP].dst}:{packet[UDP].dport} HOUR# {time}")
            check.append(packet[IP].src)

    if packet.haslayer(ARP):
        if packet[ARP].op == 1:
            print(f"##WIFI CONNECTION EVENT## -> SRC# {packet[ARP].psrc} MAC# {packet[ARP].hwsrc} HOUR# {time}")

    if packet.haslayer(Dot11Deauth):
        print(f"##WIFI DEAUTHTENTICATION EVENT## -> DST# {packet[802.11].addr1} HOUR# {time}")


sniff(prn=Detect, count=0, store=False)
#if __name__ == "__main__":
