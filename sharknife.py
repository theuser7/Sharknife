from scapy.all import sniff,TCP,UDP,ICMP,IP,ARP,Dot11Deauth

check = []
ports = [21,22,23.25]
def Detect(packet):
    if packet.haslayer(ICMP):
        if packet[ICMP].type == 8:
            print(f"ICMP ECHO-REQUEST  {packet[IP].src} -> {packet[IP].dst}")

    if packet.haslayer(TCP):
        if packet.haslayer(IP):
            if packet[TCP].flags == "S": 
                if packet[IP].src in check and packet[TCP].dport in ports:
                    print(f"TCP SYN  {packet[IP].src}:{packet[TCP].sport} -> {packet[IP].dst}:{packet[TCP].dport}")
                check.append(packet[IP].src)
            elif packet[TCP].flags == "F":
                if packet[IP].src in check and packet[TCP].dport in ports:
                    print(f"TCP FIN  {packet[IP].src}:{packet[TCP].sport} -> {packet[IP].dst}:{packet[TCP].dport}")
                check.append(packet[IP].src)

    if packet.haslayer(UDP):
        if packet.haslayer(IP):
            if packet[IP].src in check and packet[UDP].dport in ports:
                print(f"UDP CONN  {packet[IP].src}:{packet[UDP].sport} -> {packet[IP].dst}:{packet[UDP].dport}")
            check.append(packet[IP].src)

    if packet.haslayer(ARP):
        if packet[ARP].op == 1:
            print(f"ARP WHO-HAS  {packet[ARP].hwsrc} -> {packet[ARP].hwdst}")
        if packet[ARP].op == 2:
                print(f"ARP IS-AT  {packet[ARP].hwsrc} -> {packet[ARP].hwdst}")

    if packet.haslayer(Dot11Deauth):
        print(f"DOT11 WIFI DEAUTH  -> {packet[802.11].addr1}")

sniff(prn=Detect, count=0, store=False)
#if __name__ == "__main__":
