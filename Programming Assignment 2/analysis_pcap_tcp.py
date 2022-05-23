import dpkt #suggested pcap library; used naming conventions from the examples
import socket #libary to parse the byte ip into readable form vs hardcoding the ip addresses
from functools import reduce #import the reduce function to simplify the coding
from collections import defaultdict #use librabry default dict to initialize empty dict of True's

filename = 'assignment2.pcap' #filename
file = open(filename, 'rb') #open the file
pcap = dpkt.pcap.Reader(file) #read the file
tcpFlows = {} #store the data flows
rtt = {} #store the timestamps
trueReceiverPort={} #store the receiver port for each flow determined by the SYN and SYNACK
booleanFlow = defaultdict(lambda : True) #Set a default value of True for all keys in the dictionary

def parseFlow(index, flow): #parse the individual flow and print relevant data
    numberOfBytes = reduce( #folds the map function such that lambda can add them all up
                lambda x, y: x+y, #all the individual byte counts up
                   map(lambda packet: packet['byte_count'], tcpFlows[flow])) #map/lambda gathers all flows[flow['bytecount']]
    timestamps = sorted( #sort the timestamps from first to last
                map(lambda packet: packet['timestamp'], tcpFlows[flow])) #map/lambda gathers all the timestamps
    timeTaken = timestamps[-1] - timestamps[0] #subtract the first and last to find the time taken
    current = 0 #Initialize the packet we are reading
    congestionWindow = [None, None, None] #Create create congestionWindow for the first 3 sizes
    for i in range(0,3):  #loop for 3 congestion window
        count = 0 #Initialize a count of the packetes sent in the window
        window = tcpFlows[flow][current]['timestamp'] + rtt[flow] #time until the expected response window
        while tcpFlows[flow][current]['timestamp'] < window: #go until current exceeds
            if current==len(tcpFlows[flow]): #if we are on the last packet
                break #break the loop
            current=current+1 #go to  next packet
            count=count+1 #we read a packet during the window
        congestionWindow[i] = count #the first window is the # of packets read before exceeding an rtt
        if current==len(tcpFlows[flow]): #if we are on the last packet
            break #break the loop
    retransmits = 0 #store total retransmits
    tripleDupe = 0 #store retransmits due to triple dupe ack
    timeOuts = 0 #store retransmits due to time out

    #We can iterate through the packets 
    #If the current packet has a timestamp of 2RTT(aka 1RTO) more than the previous packet, we should note that it is a timeout
    #If the current packet has the same ack number as the past two packets, we should note that it is a triple duplicate ack
    #We should care about the initial two cases where there may not be previous packets

    print(f"Flow #{index} - {flow}") #a) write down port and ip for source and destination
    print(f"\tTransaction #1") #b) write the top two transactions with the seq #, ack #, and win
    print(f"\t\tSequence Number - {tcpFlows[flow][0]['tcp'].seq}") #seq # of 1
    print(f"\t\tAck Number - {tcpFlows[flow][0]['tcp'].ack}") #ack # of 1
    print(f"\t\tReceive Window - {tcpFlows[flow][0]['tcp'].win}")  #win of 1
    print(f"\tTransaction #2") #transaction #2
    print(f"\t\tSequence Number - {tcpFlows[flow][1]['tcp'].seq}") #seq # of 2
    print(f"\t\tAck Number - {tcpFlows[flow][1]['tcp'].ack}") #ack # of 2
    print(f"\t\tReceive Window Sizes - {tcpFlows[flow][1]['tcp'].win}") #win of 2
    print(f"\tThroughput: {numberOfBytes/timeTaken} bps") #c) write the sender throughput
    print(f"\tCongestion Window: {congestionWindow}") #1) Print the first 3 congestion windows
    print(f"\tTotal retransmits: {retransmits}") #2) Print the total retransmits
    print(f"\t\tRetransmits due to triple duplicate acks - {tripleDupe}") #triple duplicate acks
    print(f"\t\tRetransmits due to time outs - {timeOuts}") #time outs
    print(f"\t\tRetransmits due to other reasons - {retransmits-tripleDupe-timeOuts}") #'rare' cases
    
for timestamp, buf in pcap: #loop through the read file
    eth = dpkt.ethernet.Ethernet(buf) #use ethernet module; eth/ip/tcp naming is convention
    if eth.type != dpkt.ethernet.ETH_TYPE_IP: #prevent errors in case other pcap files are tested
        continue #we dont want to continue
    ip = eth.data #read the ip
    if ip.p != dpkt.ip.IP_PROTO_TCP: #only TCP
        continue # we dont want to continue
    if ip.p==dpkt.ip.IP_PROTO_TCP: #we only want to check tcp flows
        flows = tcpFlows #set the flows if its tcp
    tcp = ip.data #get the data of the ip
    senderIP = socket.inet_ntoa(ip.src) #get the ip of the sender
    senderPort = tcp.sport #get the port of the sender
    receiverIP = socket.inet_ntoa(ip.dst) #get receiver ip
    receiverPort = tcp.dport #get receiver port
    packet = (senderPort, senderIP), (receiverPort, receiverIP) #Store the packet as the information needed to identify which flow it is from
    packetData = { #record the data for the packet
        'byte_count': len(tcp), #bytes per packet
        'timestamp': timestamp, #timestamp received
        'tcp': tcp #store the tcp data for the packet
    } #end of data per packet
    if tcp.flags&dpkt.tcp.TH_SYN and not tcp.flags&dpkt.tcp.TH_ACK: #register the SYN
        rtt[packet] = timestamp #store the timestamp
        trueReceiverPort[packet] = receiverPort #store which port is the actual receiver for later reference
    if tcp.flags&dpkt.tcp.TH_SYN and tcp.flags&dpkt.tcp.TH_ACK: #register the SYNACK
        packet = (receiverPort, receiverIP), (senderPort, senderIP) #the packet is reversed because synack is sent the other way
        rtt[packet] = timestamp - rtt[packet]  #calculate the rtt, but leave the units in seconds for comparison with timestamp
    if(not trueReceiverPort.get(packet)): #if the packet doesn't exist, it must be from the receiver whose body is empty
        continue #skip the rest of the loop
    if(senderPort==trueReceiverPort[packet]): #ignore the packets with a sender of the receiver port, since the payload is empty(we can ignore because they are one flow)
        continue #skip the rest of the loop
    if tcp.flags&dpkt.tcp.TH_FIN: #on first encounter with a FIN, we want to stop accepting packets meaning that we do not record any packets sent after the FIN <<<ENDING PACKET
        booleanFlow[packet] = False #set the flow to false to signify the end; do not include any FIN
    if booleanFlow[packet]: #if it is still true by default, we can continue adding packets
        if flows.get(packet): #if the flow previously existed
            flows[packet].append(packetData) #we append to the end bc tcp is "in-order"
        elif tcp.flags&dpkt.tcp.TH_PUSH and tcp.flags&dpkt.tcp.TH_ACK: #PUSHACK is the first packet AFTER the three way handshake, so we want to start recording the packets <<<STARTING PACKET
            flows[packet] = [packetData] #otherwise the packet is a new flow, so we want to check if it finished the 3 way handshake
                
print(f'Total TCP flows from sender: {len(tcpFlows.keys())}') #Print the total number of flows
for index, flow in enumerate(tcpFlows.keys()): #enumerate the flows to access an index
    parseFlow(index+1, flow) #add one to index to reach a index-1 based counting and print the data for the flow
file.close() #close the files
