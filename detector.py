import dpkt
import socket

# Function from dpkt examples.print_http_requests
def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)
    
    
def synFlood():
    # must be in the same directory
    # f = open('pkt.TCP.synflood.spoofed.pcap', 'rb')
    f = open('SYN.pcap', 'rb')
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
        
        if inet_to_str(ip.src) in ipSrc and ipSrc[inet_to_str(ip.src)] >40:
            return "Syn Flood detected from IP " + inet_to_str(ip.src) + " - " + str(num) + " loop iterations completed before detected"
        
    return "No Syn FLood detected"
    





if __name__ == '__main__':
    print(synFlood())