import datetime
import os
import sys
import struct
import time
import select
import socket
import binascii

ICMP_ECHO_REQUEST = 8
rtt_min = float('+inf')
rtt_max = float('-inf')
rtt_sum = 0
rtt_cnt = 0

def checksum(string):
    csum = 0
    countTo = (len(string) / 2) * 2

    count = 0
    while count < countTo:
        thisVal = string[count + 1] * 256 + string[count]
        csum = csum + thisVal
        csum = csum & 0xffffffff
        count = count + 2

    if countTo < len(string):
        csum = csum + ord(string[len(str) - 1])
        csum = csum & 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def receiveOnePing(mySocket, ID, timeout, destAddr):
    global rtt_min, rtt_max, rtt_sum, rtt_cnt
    timeLeft = timeout
    while 1:
        startedSelect = time.time()
        whatReady = select.select([mySocket], [], [], timeLeft)
        howLongInSelect = (time.time() - startedSelect)
        if whatReady[0] == []:  # Timeout
            return "Request timed out."

        timeReceived = time.time()
        recPacket, addr = mySocket.recvfrom(1024)

        # TODO
        # Fetch the ICMP header from the IP packet

        identifier = struct.unpack('h', recPacket[24:26])[0] #get the id portion of the icmp header(bit 192//byte 24 is where the id starts and it ends 2 bytes later)
        if ID == identifier: #in case of packet loss and the ids do not match; assumes everything else fits if the id matches
            length = len(recPacket)
            timeSent = struct.unpack('d',recPacket[28:36])[0] #assume payload of ping is going to be timestamp
            rtt = (timeReceived - timeSent)*1000 #get rtt of packet in ms
            if(rtt>rtt_max): #determine if new max
                rtt_max = rtt
            if(rtt<rtt_min): #determine if new min
                rtt_min = rtt
            rtt_sum = rtt_sum + rtt #increase total rtt
            rtt_cnt = rtt_cnt + 1 #increase count
            return str(length) + " bytes from " + destAddr + "; time=" + str(round(rtt,1)) +" ms" #not technically delay, but we want to print the correct output
    
        # TODO END

        timeLeft = timeLeft - howLongInSelect
        if timeLeft <= 0:
            return "Request timed out."


def sendOnePing(mySocket, destAddr, ID):
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)

    myChecksum = 0
    # Make a dummy header with a 0 checksum.
    # struct -- Interpret strings as packed binary data
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    data = struct.pack("d", time.time())    # 8 bytes
    # Calculate the checksum on the data and the dummy header.
    myChecksum = checksum(header + data)

    # Get the right checksum, and put in the header
    if sys.platform == 'darwin':
        myChecksum = socket.htons(myChecksum) & 0xffff
        # Convert 16-bit integers from host to network byte order.
    else:
        myChecksum = socket.htons(myChecksum)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    packet = header + data

    mySocket.sendto(packet, (destAddr, 1))  # AF_INET address must be tuple, not str
    # Both LISTS and TUPLES consist of a number of objects
    # which can be referenced by their position number within the object


def doOnePing(destAddr, timeout):
    icmp = socket.getprotobyname("icmp")
    # SOCK_RAW is a powerful socket type. For more details see: http://sock-raw.org/papers/sock_raw

    # TODO
    # Create Socket here
    
    mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
    
    # TODO END

    myID = os.getpid() & 0xFFFF  # Return the current process i
    sendOnePing(mySocket, destAddr, myID)
    delay = receiveOnePing(mySocket, myID, timeout, destAddr)

    mySocket.close()
    return delay


def ping(host, timeout=1):
    global rtt_min, rtt_max, rtt_sum, rtt_cnt
    cnt = 0
    # timeout=1 means: If one second goes by without a reply from the server,
    # the client assumes that either the client's ping or the server's pong is lost
    dest = socket.gethostbyname(host)
    print("Pinging " + dest + " using Python:")
    # Send ping requests to a server separated by approximately one second
    try:
        while True:
            cnt += 1
            print(doOnePing(dest, timeout))
            time.sleep(1)
    except KeyboardInterrupt:
        # TODO
        # calculate statistic here

        print("--- " + dest + " ping statistics ---")
        if(rtt_cnt==0):
            print("No packets sent")
        else:
            print("round trip min/avg/max " + str(round(rtt_min,3)) + "/" + str(round(rtt_sum/rtt_cnt,3)) + "/" + str(round(rtt_max,3)) + " ms")
        
        # TODO END

#argument="stonybrook.edu" #legacy code because running from terminal was a lot of work >:)

if __name__ == '__main__':
    ping(sys.argv[1])
