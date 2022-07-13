from scapy.all import sniff,TCP,UDP,ICMP,IP,ARP,Dot11Deauth

check = []
ports = [21,22,23.25]
def Detect(packet):
    if packet.haslayer(ICMP):
        if packet[ICMP].type == 8:
            print(packet.summary())

    if packet.haslayer(TCP):
        if packet.haslayer(IP):
            if packet[TCP].flags == "S": 
                if packet[IP].src in check and packet[TCP].dport in ports:
                    print(packet.summary())
                check.append(packet[IP].src)
            elif packet[TCP].flags == "F":
                if packet[IP].src in check and packet[TCP].dport in ports:
                    print(packet.summary())
                check.append(packet[IP].src)

    if packet.haslayer(UDP):
        if packet.haslayer(IP):
            if packet[IP].src in check and packet[UDP].dport in ports:
                print(packet.summary())
            check.append(packet[IP].src)

    if packet.haslayer(ARP):
        if packet[ARP].op == 1:
            print(packet.summary())
        if packet[ARP].op == 2:
                print(packet.summary())

    if packet.haslayer(Dot11Deauth):
        print(packet.summary())

sniff(prn=Detect, count=0, store=False)
#if __name__ == "__main__":
