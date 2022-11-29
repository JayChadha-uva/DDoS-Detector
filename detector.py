import dpkt
import socket

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
                
        elif (not (tcp.flags & dpkt.tcp.TH_ACK) and (tcp.flags & dpkt.tcp.TH_SYN)):
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
                
        if (synCounter - synAckCounter > 100 and synCounter - ackCounter > 100):
            return "Syn flood detected - three way handshake could not be completed. " + str(num) + " loop iterations completed before detected"
        
        if inet_to_str(ip.src) in ipSrc and ipSrc[inet_to_str(ip.src)] >60:
            return "Syn Flood detected from IP " + inet_to_str(ip.src) + " - " + str(num) + " loop iterations completed before detected"
        
    return "No Syn Flood detected"

def synAckFlood(input:str):
    f = open(input, 'rb')
    pcap = dpkt.pcap.Reader(f)
    
    ipDst = {}
    synAckSeen = {}    
    synCounter = 0
    
    for num, (ts, buff) in  enumerate(pcap):
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
                
                if  synAckSeen[inet_to_str(ip.dst)] - temp > 60:
                    return "Syn Ack Flood detected flooding destination " + inet_to_str(ip.dst) + " - " + str(num) + " loop iterations completed before detected"         
                
        elif (not (tcp.flags & dpkt.tcp.TH_ACK) and (tcp.flags & dpkt.tcp.TH_SYN)):
            synCounter += 1
                       
            if inet_to_str(ip.dst) not in ipDst:
                ipDst[inet_to_str(ip.dst)] = 1
            else:
                ipDst[inet_to_str(ip.dst)] = ipDst[inet_to_str(ip.dst)] + 1
                              
    return "No SynAck Flood detected"    

def nullUDP(input:str):
    f = open(input, 'rb')
    pcap = dpkt.pcap.Reader(f)
    badUpdLength = 0
    goodUpdLength = 0
    
    for num, (ts, buff) in  enumerate(pcap):
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
        
        if udp.ulen == 0:
            badUpdLength +=1
        else:
            goodUpdLength +=1 
            
        if badUpdLength-goodUpdLength > 60:
            return "Null UDP length. UDP lenght must be >0. Loop iterations failed after " + str(num) + " iterations."
   
    return "No null UDP length detected"

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
                if inet_to_str(ip.dst) in ipDst and ipDst[inet_to_str(ip.dst)] > 60 and delta < 0.5:
                    return "ICMP flood of type 8 (echo). "+ inet_to_str(ip.dst) + " flooded with echo requests. " + str(num) + " loop iterations before detected, " + str(delta) + " seconds."

    return "No ICMP echo flood detected"

def runTests(input:str):
    
    print("Tests results for: " + input)
    print("----------------------------")
    print(synFlood(input))
    print(synAckFlood(input))
    print(nullUDP(input))
    print(icmpEcho(input))
    print("\n")
    

if __name__ == '__main__':
    
    print("\n")
    runTests("SYN.pcap")
    
    runTests("pkt.TCP.synflood.spoofed.pcap")
    runTests("part1.pcap")
    runTests("pkt.ICMP.largeempty.pcap")
    runTests('amp.TCP.syn.optionallyACK.optionallysamePort.pcapng')
    runTests('pkt.TCP.DOMINATE.syn.ecn.cwr.pcapng')
    runTests('amp.TCP.reflection.SYNACK.pcap')
    runTests('pkt.UDP.null.pcapng')
    