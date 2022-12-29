# DDoS Detector

The approach we chose for preventing DDoS attacks is to use network analysis tools to analyze DDoS packet capture (PCAP) files and identify patterns in the attack traffic. This allowed us to identify the source of the attack and take appropriate measures to block the malicious traffic and protect the network.

First, PCAP files contain detailed information about network traffic, including the source and destination of each packet, the type of packet (e.g., SYN, ACK, UDP, ICMP), and the payload of the packet. This information can be used to identify patterns in the network traffic that may indicate a DDoS attack.

### Types of Attacks Detected 

SYN flood attacks are a type of DDoS attack that involve sending a large number of SYN packets (a type of packet used to initiate a network connection) to a target server, with the goal of overwhelming the server and preventing it from responding to legitimate requests. By analyzing PCAP files, we were able to look for an unusually high number of SYN packets coming from a single source, or a large number of SYN packets being sent to a single destination, which may indicate a SYN flood attack.

SYN-ACK attacks involve sending SYN packets to a server and then immediately sending ACK packets (a type of packet used to acknowledge a connection request) in response, with the goal of overwhelming the server's resources and preventing it from responding to legitimate requests. By analyzing PCAP files, you can look for an unusually high number of SYN and ACK packets being sent between a single source and destination, which may indicate a SYN-ACK attack.

Null UDP header attacks, which involves sending UDP packets (a type of packet used for transmitting data on a network) with a null header to a target server. Because these packets have no header, the server cannot process them and must discard them, which can consume its resources and make it unavailable to handle legitimate requests. By analyzing PCAP files, you can look for an unusually high number of UDP packets with null headers being sent to a single destination, which may indicate a null UDP header attack.

Same UDP flood attack, the attacker sends a large number of UDP packets, typically with spoofed source addresses, to a targeted server in an attempt to overwhelm it and prevent it from processing legitimate requests. By analyzing the PCAP files, it is possible to identify patterns in the network traffic that can indicate a same UDP header flood attack is taking place. This attack can be prevented by blocking the IP addresses of the attackers or increasing the server's capacity to handle incoming requests.

ICMP (Internet Control Message Protocol) echo request flood attack, which involves an attacker sending a large number of ICMP echo requests to a targeted server in an attempt to overwhelm it and make it unavailable to legitimate users. By analyzing PCAP files for signs of an ICMP echo request flood attack, we were able to identify the source of the attack. Identifying the source of this attack and taking steps to mitigate it can help prevent the attack from causing significant disruption to the targeted server or network.

Since in the real world it is difficult to record for a DDoS attack due to the inability to predict when an attack could occur, the PCAP files we analyzed came from a dataset that models DDoS attacks. This dataset allows for researchers to analyze attacks and trends that display the occurrence of a DDoS attack. Additionally, we used a PCAP file from the homework “part1.pcap” in order to check that it does not trigger any of the tests, ensuring our program does not trigger any false positives.

