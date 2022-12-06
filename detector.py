from contextlib import redirect_stdout
import socket
import dpkt

def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)
    
def synFlood(input:str):
    f = open(input, 'rb')
    pcap = dpkt.pcap.Reader(f)
    
    ipDst = {}
    ipSrc = {}
    synAckSeen = set()
    ackDict = set()
    
    synCounter = 0
    synAckCounter = 0
    ackCounter = 0
    
    for num, (ts, buff) in  enumerate(pcap):
        if num == 0:
            start = ts
        try:
            eth = dpkt.ethernet.Ethernet(buff)
        except:
            continue
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue
        ip = eth.data
        if ip.p != dpkt.ip.IP_PROTO_TCP:
            continue
        tcp = ip.data
        
        if ((tcp.flags & dpkt.tcp.TH_ACK) and (tcp.flags & dpkt.tcp.TH_SYN)):
            
            if inet_to_str(ip.src) not in synAckSeen:
                synAckCounter += 1
                synAckSeen.add(inet_to_str(ip.src))
                
        elif (not (tcp.flags & dpkt.tcp.TH_ACK) and (tcp.flags & dpkt.tcp.TH_SYN ) and not(tcp.flags & dpkt.tcp.TH_CWR)):
            synCounter += 1
            
            if inet_to_str(ip.src) not in ipSrc:
                ipSrc[inet_to_str(ip.src)] = 1    
            else:
                ipSrc[inet_to_str(ip.src)] = ipSrc[inet_to_str(ip.src)] + 1
            
            if inet_to_str(ip.dst) not in ipDst:
                ipDst[inet_to_str(ip.dst)] = 1
            else:
                ipDst[inet_to_str(ip.dst)] = ipDst[inet_to_str(ip.dst)] + 1 
            
        elif ((tcp.flags & dpkt.tcp.TH_ACK) and not (tcp.flags & dpkt.tcp.TH_SYN)):
            if inet_to_str(ip.dst) not in ackDict:
                ackCounter +=1
                ackDict.add(inet_to_str(ip.dst))  
                
        delta = ts - start
        if (synCounter - synAckCounter > 200 and synCounter - ackCounter > 200):
            return "SYN flood detected - three way handshake could not be completed." + " - " + str(delta) + " seconds."
        
        if inet_to_str(ip.src) in ipSrc and ipSrc[inet_to_str(ip.src)] >100:
            return "SYN Flood detected from IP " + inet_to_str(ip.src) + " - " + str(delta) + " seconds."
        
    return "No SYN Flood detected"

def synAckFlood(input:str):
    f = open(input, 'rb')
    pcap = dpkt.pcap.Reader(f)
    
    ipDst = {}
    synAckSeen = {}
    synCounter = 0
    
    for num, (ts, buff) in  enumerate(pcap):
        if num == 0:
            start = ts
        try:
            eth = dpkt.ethernet.Ethernet(buff)
        except:
            continue
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue
        ip = eth.data
        if ip.p != dpkt.ip.IP_PROTO_TCP:
            continue
        tcp = ip.data
        
        if ((tcp.flags & dpkt.tcp.TH_ACK) and (tcp.flags & dpkt.tcp.TH_SYN)):        
            if inet_to_str(ip.dst) not in synAckSeen:
                synAckSeen[inet_to_str(ip.dst)] = 1
    
            else:
                synAckSeen[inet_to_str(ip.dst)] = synAckSeen[inet_to_str(ip.dst)] + 1
                
                temp = 0
                if inet_to_str(ip.dst) in ipDst:
                    temp = ipDst[inet_to_str(ip.dst)]
                
                if  synAckSeen[inet_to_str(ip.dst)] - temp > 100:
                    delta = ts - start
                    return "SYN ACK Flood detected flooding destination " + inet_to_str(ip.dst) + " - " + str(delta) + " seconds."       
                
        elif (not (tcp.flags & dpkt.tcp.TH_ACK) and (tcp.flags & dpkt.tcp.TH_SYN)):
            synCounter += 1
                       
            if inet_to_str(ip.dst) not in ipDst:
                ipDst[inet_to_str(ip.dst)] = 1
            else:
                ipDst[inet_to_str(ip.dst)] = ipDst[inet_to_str(ip.dst)] + 1
                              
    return "No SYN ACK Flood detected" 

def synCwrFlood(input:str):
    f = open(input, 'rb')
    pcap = dpkt.pcap.Reader(f)
    
    ipDst = {}
    ipSrc = {}
    synAckSeen = set()
    ackDict = set()
    
    synCounter = 0
    synAckCounter = 0
    ackCounter = 0
    
    for num, (ts, buff) in  enumerate(pcap):
        if num == 0:
            start = ts
        try:
            eth = dpkt.ethernet.Ethernet(buff)
        except:
            continue
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue
        ip = eth.data
        if ip.p != dpkt.ip.IP_PROTO_TCP:
            continue
        tcp = ip.data
        
        if ((tcp.flags & dpkt.tcp.TH_ACK) and (tcp.flags & dpkt.tcp.TH_SYN)):
            
            if inet_to_str(ip.src) not in synAckSeen:
                synAckCounter += 1
                synAckSeen.add(inet_to_str(ip.src))
                
        elif (not (tcp.flags & dpkt.tcp.TH_ACK) and (tcp.flags & dpkt.tcp.TH_SYN ) and (tcp.flags & dpkt.tcp.TH_CWR)):
            synCounter += 1
            
            if inet_to_str(ip.src) not in ipSrc:
                ipSrc[inet_to_str(ip.src)] = 1    
            else:
                ipSrc[inet_to_str(ip.src)] = ipSrc[inet_to_str(ip.src)] + 1
            
            if inet_to_str(ip.dst) not in ipDst:
                ipDst[inet_to_str(ip.dst)] = 1
            else:
                ipDst[inet_to_str(ip.dst)] = ipDst[inet_to_str(ip.dst)] + 1 
            
        elif ((tcp.flags & dpkt.tcp.TH_ACK) and not (tcp.flags & dpkt.tcp.TH_SYN)):
            if inet_to_str(ip.dst) not in ackDict:
                ackCounter +=1
                ackDict.add(inet_to_str(ip.dst))  
                
        delta = ts - start
        if (synCounter - synAckCounter > 200 and synCounter - ackCounter > 200):
            return "SYN CWR flood detected - three way handshake could not be completed." + " - " + str(delta) + " seconds."
        
        if inet_to_str(ip.src) in ipSrc and ipSrc[inet_to_str(ip.src)] >100:
            return "SYN CWR Flood detected from IP " + inet_to_str(ip.src) + " - " + str(delta) + " seconds."
        
    return "No SYN CWR Flood detected"
   

def nullUDP(input:str):
    f = open(input, 'rb')
    pcap = dpkt.pcap.Reader(f)
    
    badUpdLength = 0
    goodUpdLength = 0
    
    for num, (ts, buff) in  enumerate(pcap):
        if num == 0:
            start = ts
        try:
            eth = dpkt.ethernet.Ethernet(buff)
        except:
            continue
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue
        ip = eth.data
        if ip.p != dpkt.ip.IP_PROTO_UDP:
            continue
        udp = ip.data
        
        if type(udp)!=bytes and udp.ulen == 0:
            badUpdLength +=1
        else:
            goodUpdLength +=1 
            
        if badUpdLength-goodUpdLength > 60:
            delta = ts - start
            return "Null UDP length. UDP length must be >0. - " + str(delta) + " seconds."
   
    return "No null UDP length flood detected"

def icmpEcho(input:str):
    f = open(input, 'rb')
    pcap = dpkt.pcap.Reader(f)
    
    ipDst={}
    start = 0
    
    for num, (ts, buff) in  enumerate(pcap):
        if num == 0:
            start = ts
        try:
            eth = dpkt.ethernet.Ethernet(buff)
        except:
            continue
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue
        ip = eth.data
        
        if isinstance(ip.data, dpkt.icmp.ICMP):
            icmp = ip.data
            if icmp.type == 8:
                if inet_to_str(ip.dst) not in ipDst:
                    ipDst[inet_to_str(ip.dst)] = 1
                else:
                    ipDst[inet_to_str(ip.dst)] = ipDst[inet_to_str(ip.dst)] + 1
          
                delta = ts - start
                if inet_to_str(ip.dst) in ipDst and ipDst[inet_to_str(ip.dst)] > 60 and delta < 0.1:
                    return "ICMP flood of type 8 (echo). "+ inet_to_str(ip.dst) + " flooded with echo requests. - " + str(delta) + " seconds."
                
    return "No ICMP echo flood detected"

def sameUDPLength(input:str):
    f = open(input, 'rb')
    pcap = dpkt.pcap.Reader(f)

    udpLength = {}
    
    for num, (ts, buff) in  enumerate(pcap):
        if num == 0:
            start = ts
        try:
            eth = dpkt.ethernet.Ethernet(buff)
        except:
            continue
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue
        ip = eth.data
        if ip.p != dpkt.ip.IP_PROTO_UDP:
            continue
        udp = ip.data  
        
        if type(udp)!=bytes and udp.ulen in udpLength:
            udpLength[udp.ulen] = udpLength[udp.ulen] +1
            delta = ts - start
            if udpLength[udp.ulen] == 200 and num<600 and delta <0.1:
                return "UDP flood of same length detected. " + inet_to_str(ip.dst) + " flooded with same UDP length packets. - "+ str(delta) + " seconds."
        elif type(udp)!=bytes:
            udpLength[udp.ulen] = 1
   
    return "No same UDP length flood detected"

def runTests(input:str):
    print("Tests results for: " + input)
    print("---------------------------------")
    print(synFlood(input))
    print(synAckFlood(input))
    print(synCwrFlood(input))
    print(nullUDP(input))
    print(sameUDPLength(input))
    print(icmpEcho(input))
    print("\n")
    

if __name__ == '__main__':
    with open('out.txt', 'w') as f:
        with redirect_stdout(f):
            runTests("SYN.pcap")
            runTests("pkt.TCP.synflood.spoofed.pcap")
            runTests("part1.pcap")
            runTests("pkt.ICMP.largeempty.pcap")
            runTests('amp.TCP.syn.optionallyACK.optionallysamePort.pcapng')
            runTests('pkt.TCP.DOMINATE.syn.ecn.cwr.pcapng')
            runTests('amp.TCP.reflection.SYNACK.pcap')
            runTests('pkt.UDP.null.pcapng')
            runTests('pkt.UDP.rdm.fixedlength.pcapng')
            runTests('amp.UDP.UBNT.src10001.pcapng')
            runTests('amp.dns.RRSIG.fragmented.pcap')
    